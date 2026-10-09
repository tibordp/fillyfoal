//! Page-layout documents: Adobe InDesign (master pages and contiguous
//! objects, with the embedded XMP packet), QuarkXPress, Xara (record
//! stream) and Scribus (XML). (Standalone XMP lives in `image::xmp`.)

use crate::bytes::{u16_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{ChunkLayout, Cursor};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::{probe, xml};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::{hex, text, uint};

// ---------------------------------------------------------------------------
// Adobe InDesign

const MASTER_GUID: &[u8; 16] = b"\x06\x06\xed\xf5\xd8\x1d\x46\xe5\xbd\x31\xef\xe7\xfe\x74\xb7\x1d";
const OBJECT_HEADER: &[u8; 16] =
    b"\xde\x39\x39\x79\x51\x88\x4b\x6c\x8e\x63\xee\xf8\xae\xe0\xdd\x38";
const OBJECT_TRAILER: &[u8; 16] =
    b"\xfd\xce\xdb\x70\xf7\x86\x4b\x4f\xa4\xd3\xc7\x28\xb3\x41\x71\x9c";
const PAGE: u64 = 4096;

declare_format!(pub INDESIGN = "indesign", "Adobe InDesign document", ["indd", "indt", "indb", "indl"], "application/x-indesign",
    Probe::Custom(|h| h.starts_with(MASTER_GUID)), indesign);

/// The fields of one master page that matter: type, byte order, sequence
/// number, page count.
fn master(d: &[u8]) -> (String, u8, u64, u32) {
    (
        crate::text::latin1(d.get(16..24).unwrap_or_default()),
        d.get(24).copied().unwrap_or(0),
        u64_le(d, 0x108).unwrap_or(0),
        u32_le(d, 0x118).unwrap_or(0),
    )
}

async fn indesign(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut current = (0u64, 0u32, String::new());
    for i in 0..2u64 {
        let span = file.sub(i.saturating_mul(PAGE), PAGE);
        let d = cx.read(span.sub(0, 0x11c)).await?;
        if !d.starts_with(MASTER_GUID) {
            cx.emit(
                Node::new(format!("Master page {i}"))
                    .span(span)
                    .diag(Diagnostic::malformed("master page GUID missing")),
            );
            continue;
        }
        let (kind, _, seq, pages) = master(&d);
        if seq >= current.0 {
            current = (seq, pages, kind.clone());
        }
        cx.emit(
            Node::new(format!("Master page {i}"))
                .span(span)
                .summary(format!("{kind}, sequence {seq}, {pages} pages"))
                .lazy(master_fields, span),
        );
    }
    let (_, pages, kind) = current;
    let db_end = u64::from(pages).saturating_mul(PAGE);
    cx.emit(
        Node::new("Database pages")
            .span(file.sub(2 * PAGE, db_end.saturating_sub(2 * PAGE)))
            .summary(format!("{} pages of 4 KiB", pages.saturating_sub(2))),
    );
    // Contiguous objects follow the database: header GUID, UID, class,
    // stream length, checksum; the stream; a trailer.
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    cur.seek(db_end);
    let mut objects = 0u32;
    while cur.remaining() >= 32 {
        let start = cur.pos();
        let head = cur.bytes(32).await?;
        if !head.starts_with(OBJECT_HEADER) {
            cx.emit(Node::new("Trailing data").span(file.tail(start)));
            break;
        }
        let uid = u32_le(&head, 16).unwrap_or(0);
        let class = u32_le(&head, 20).unwrap_or(0);
        let len = u64::from(u32_le(&head, 24).unwrap_or(0));
        let stream = cur.span(len);
        if stream.len < len {
            return Err(Diagnostic::truncated(
                Span::new(stream.source, stream.offset, len),
                stream.len,
            ));
        }
        cur.skip(len);
        let trailer = cur.peek(16).await?;
        if trailer.as_slice() == OBJECT_TRAILER.as_slice() {
            cur.skip(32);
        }
        objects = objects.saturating_add(1);
        // A stream starting with a length then "<?xpacket" is the XMP packet.
        let peek = cx.read_avail(stream.sub(0, 16)).await?;
        let node = Node::new(format!("Object {uid}"))
            .span(cur.since(start))
            .summary(format!("class {class:#x}, {len} bytes"));
        let node = if peek.get(4..13) == Some(b"<?xpacket".as_slice()) {
            let xmp = stream.tail(4);
            node.summary("XMP metadata").lazy(xmp_child, (input, xmp))
        } else {
            node
        };
        cx.push(node).await;
    }
    let kind = match kind.trim() {
        "DOCUMENT" => "document",
        "BOOKBOOK" => "book",
        other => other,
    };
    cx.annotate(format!(
        "Adobe InDesign {kind}, {pages} database pages, {objects} contiguous objects"
    ));
    Ok(())
}

async fn xmp_child(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    cx.emit(embedded("XMP packet", input.nested(span)));
    Ok(())
}

async fn master_fields(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read(span.sub(0, 0x11c)).await?;
    let (kind, endian, seq, pages) = master(&d);
    cx.emit(
        Node::new("GUID")
            .span(span.sub(0, 16))
            .value(Value::Bytes(d.get(..16).unwrap_or_default().to_vec()))
            .summary("master page"),
    );
    cx.emit(Node::new("Type").span(span.sub(16, 8)).value(text(kind)));
    cx.emit(
        Node::new("Object stream byte order")
            .span(span.sub(24, 1))
            .value(Value::Enum {
                raw: endian.into(),
                bits: 8,
                name: match endian {
                    1 => Some("little-endian"),
                    2 => Some("big-endian"),
                    _ => None,
                },
            }),
    );
    cx.emit(
        Node::new("Sequence number")
            .span(span.sub(0x108, 8))
            .value(uint(seq, 64))
            .desc("The master page with the higher number is current"),
    );
    cx.emit(
        Node::new("File pages")
            .span(span.sub(0x118, 4))
            .value(uint(pages, 32)),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// QuarkXPress

fn quark_probe(h: &Head<'_>) -> bool {
    (h.at(2, b"MMXPR") || h.at(2, b"IIXPR"))
        && h.data.get(7).is_some_and(|c| c.is_ascii_alphanumeric())
}

declare_format!(pub QUARK = "quarkxpress", "QuarkXPress document", ["qxd", "qxp", "qxt"], "application/vnd.Quark.QuarkXPress",
    Probe::Custom(quark_probe), quark);

async fn quark(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let d = cx.read(file.sub_exact(0, 16)?).await?;
    let big = d.get(2) == Some(&b'M');
    cx.emit(
        Node::new("Reserved")
            .span(file.sub(0, 2))
            .value(hex(u16_be(&d, 0).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Byte order")
            .span(file.sub(2, 2))
            .value(text(if big {
                "MM (big-endian, Mac)"
            } else {
                "II (little-endian, Windows)"
            })),
    );
    cx.emit(
        Node::new("Signature")
            .span(file.sub(4, 4))
            .value(text(String::from_utf8_lossy(
                d.get(4..8).unwrap_or_default(),
            ))),
    );
    let version = if big {
        u16_be(&d, 8)
    } else {
        d.get(8..10).map(|b| {
            u16::from_le_bytes([
                b.first().copied().unwrap_or(0),
                b.get(1).copied().unwrap_or(0),
            ])
        })
    }
    .unwrap_or(0);
    cx.emit(
        Node::new("Version code")
            .span(file.sub(8, 2))
            .value(hex(version, 16)),
    );
    cx.emit(
        Node::new("Document data")
            .span(file.tail(10))
            .diag(Diagnostic::unsupported("QuarkXPress document records")),
    );
    cx.annotate(format!(
        "QuarkXPress document ({}, version code {version:#x})",
        if big { "Mac" } else { "Windows" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Xara

declare_format!(pub XARA = "xara", "Xara document", ["xar", "web"], "application/vnd.xara",
    Probe::Magic(&[(0, b"XARA\xa3\xa3\r\n")]), xara);

const XARA_TAGS: &[(u32, &str)] = &[
    (0, "Up"),
    (1, "Down"),
    (2, "File header"),
    (3, "End of file"),
];

async fn xara(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 8)));
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    cur.seek(8);
    let mut depth = 0u32;
    let (mut records, mut kind) = (0u32, String::new());
    while let Some(chunk) = cur.chunk(ChunkLayout::new(4, 4, Endian::Little)).await? {
        let tag = u32_le(&chunk.id, 0).unwrap_or(0);
        let name = XARA_TAGS
            .iter()
            .find(|(k, _)| *k == tag)
            .map_or_else(|| format!("Record {tag}"), |(_, v)| (*v).to_owned());
        let mut node = Node::new(name)
            .span(chunk.span)
            .summary(format!("depth {depth}, {} bytes", chunk.body.len));
        match tag {
            0 => depth = depth.saturating_sub(1),
            1 => depth = depth.saturating_add(1),
            2 => {
                let h = cx.read_avail(chunk.body.sub(0, 64)).await?;
                kind = String::from_utf8_lossy(h.get(..3).unwrap_or_default()).into_owned();
                let producer: Vec<String> = h
                    .get(15..)
                    .unwrap_or_default()
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .take(3)
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                node = node.value(text(kind.clone()));
                if !producer.is_empty() {
                    node = node.summary(producer.join(" "));
                }
            }
            _ => {}
        }
        records = records.saturating_add(1);
        cx.push(node).await;
        if tag == 3 {
            break;
        }
    }
    cx.annotate(format!(
        "Xara document{}, {records} records",
        if kind.is_empty() {
            String::new()
        } else {
            format!(" ({kind})")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Scribus (an XML vocabulary)

fn scribus_probe(h: &Head<'_>) -> bool {
    probe::is_text(h)
        && xml::root(h)
            .is_some_and(|r| r.is(b"SCRIBUSUTF8NEW") || r.is(b"SCRIBUSUTF8") || r.is(b"SCRIBUS"))
}

declare_format!(pub SCRIBUS = "scribus", "Scribus document", ["sla", "scd"], "application/vnd.scribus",
    Probe::Custom(scribus_probe), scribus);

/// The value of attribute `name` in the start tag `tag` of `head`.
fn attr(head: &[u8], tag: &[u8], name: &str) -> Option<String> {
    let at = probe::find(head, tag)?;
    let head = head.get(at..)?;
    let end = head.iter().position(|&b| b == b'>').unwrap_or(head.len());
    let head = head.get(..end)?;
    let needle = format!(" {name}=\"");
    let p = probe::find(head, needle.as_bytes())?.saturating_add(needle.len());
    let rest = head.get(p..)?;
    let close = rest.iter().position(|&b| b == b'"')?;
    Some(String::from_utf8_lossy(rest.get(..close)?).into_owned())
}

async fn scribus(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 4096)).await?;
    let version = attr(&head, b"<SCRIBUS", "Version").unwrap_or_default();
    let title = attr(&head, b"<DOCUMENT", "TITLE").filter(|t| !t.is_empty());
    let pages = attr(&head, b"<DOCUMENT", "ANZPAGES");
    xml::dissect(cx.clone(), input).await?;
    cx.annotate(format!(
        "Scribus document {version}{}{}",
        title.map(|t| format!(", {t:?}")).unwrap_or_default(),
        pages.map(|p| format!(", {p} pages")).unwrap_or_default()
    ));
    Ok(())
}
