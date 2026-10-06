//! LHA / LZH archives (header levels 0, 1 and 2).
//!
//! Members follow each other: a header naming the method (`-lh5-` etc.),
//! sizes, time and name, then the compressed data; a zero byte ends the
//! archive. Levels 1 and 2 carry extended headers (file name, directory,
//! Unix permissions, ...). Stored members (`-lh0-`, `-lz4-`) are dissected in
//! place; LZSS/Huffman methods are unsupported leaves.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{
    ByteReader, count, emit_nodes, hex, human_size, text, unix_mode, unsupported,
};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
/// Extended headers per member before giving up.
const MAX_EXT: usize = 256;

pub static FORMAT: Format = Format {
    name: "lha",
    title: "LHA archive",
    extensions: &["lzh", "lha", "lzs"],
    mime: "application/x-lzh-compressed",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn is_method(m: &[u8]) -> bool {
    matches!(
        m,
        [b'-', b'l', b'h' | b'z', _, b'-'] | [b'-', b'p', b'm', _, b'-']
    )
}

fn probe(h: &Head<'_>) -> bool {
    h.data.get(2..7).is_some_and(is_method)
        && h.data.get(20).is_some_and(|&l| l <= 2)
        && h.data.first().is_some_and(|&s| s >= 21)
}

const OS_ID: EnumTable = &[
    (b'M' as u64, "MS-DOS"),
    (b'2' as u64, "OS/2"),
    (b'9' as u64, "OS-9"),
    (b'K' as u64, "OS/68K"),
    (b'3' as u64, "OS/386"),
    (b'H' as u64, "Human68K"),
    (b'U' as u64, "Unix"),
    (b'C' as u64, "CP/M"),
    (b'F' as u64, "FLEX"),
    (b'm' as u64, "Macintosh"),
    (b'R' as u64, "Runser"),
    (b'w' as u64, "Windows 95"),
    (b'W' as u64, "Windows NT"),
    (b'J' as u64, "Java"),
    (b'a' as u64, "Amiga"),
];

const EXT_TYPES: EnumTable = &[
    (0x00, "Common"),
    (0x01, "File name"),
    (0x02, "Directory name"),
    (0x3f, "Comment"),
    (0x40, "MS-DOS attributes"),
    (0x41, "Windows timestamps"),
    (0x42, "File sizes"),
    (0x50, "Unix permissions"),
    (0x51, "Unix group and user ID"),
    (0x52, "Unix group name"),
    (0x53, "Unix user name"),
    (0x54, "Unix modification time"),
];

fn stored(method: &str) -> bool {
    matches!(method, "-lh0-" | "-lz4-" | "-pm0-")
}

/// What the walk learns about a member.
struct Member {
    span: Span,
    level: u8,
    method: String,
    name: String,
    original: u64,
    directory: bool,
}

/// The extended headers of levels 1 and 2: (type, data) pairs and the total
/// size.
async fn ext_headers(cur: &mut Cursor<'_>, first: u16) -> Result<(Vec<(u8, Vec<u8>)>, u64)> {
    let mut out = Vec::new();
    let mut next = first;
    let mut total = 0u64;
    while next != 0 && out.len() < MAX_EXT {
        if next < 3 {
            return Err(
                Diagnostic::malformed("extended header shorter than 3 bytes").at(cur.span(3)),
            );
        }
        let h = cur.bytes(next.into()).await?;
        total = total.saturating_add(next.into());
        let kind = h.first().copied().unwrap_or(0);
        let body = h
            .get(1..h.len().saturating_sub(2))
            .unwrap_or_default()
            .to_vec();
        next = u16_le(&h, h.len().saturating_sub(2)).unwrap_or(0);
        out.push((kind, body));
    }
    Ok((out, total))
}

fn path_from(exts: &[(u8, Vec<u8>)]) -> (Option<String>, Option<String>) {
    let mut name = None;
    let mut dir = None;
    for (kind, body) in exts {
        match kind {
            0x01 => name = Some(String::from_utf8_lossy(body).into_owned()),
            0x02 => {
                let d: Vec<u8> = body
                    .iter()
                    .map(|&b| if b == 0xff { b'/' } else { b })
                    .collect();
                dir = Some(String::from_utf8_lossy(&d).into_owned());
            }
            _ => {}
        }
    }
    (name, dir)
}

async fn next_member(cur: &mut Cursor<'_>) -> Result<Option<Member>> {
    let start = cur.pos();
    let first = cur.peek(22).await?;
    if first.first().copied().unwrap_or(0) == 0 {
        return Ok(None);
    }
    let level = first.get(20).copied().unwrap_or(0);
    let method = String::from_utf8_lossy(first.get(2..7).unwrap_or_default()).into_owned();
    let compressed = u64::from(u32_le(&first, 7).unwrap_or(0));
    let original = u64::from(u32_le(&first, 11).unwrap_or(0));
    let (mut name, data_len) = match level {
        0 | 1 => {
            let size = u64::from(first.first().copied().unwrap_or(0));
            let header = cur.bytes(size.saturating_add(2)).await?;
            let name_len = usize::from(header.get(21).copied().unwrap_or(0));
            let name = header
                .get(22..22usize.saturating_add(name_len))
                .unwrap_or_default();
            let name = String::from_utf8_lossy(name).replace('\\', "/");
            if level == 0 {
                (name, compressed)
            } else {
                let next = u16_le(&header, header.len().saturating_sub(2)).unwrap_or(0);
                let (exts, total) = ext_headers(cur, next).await?;
                let (n, d) = path_from(&exts);
                let name = join(d, n.unwrap_or(name));
                // Level 1 counts extended headers in the compressed size.
                (name, compressed.saturating_sub(total))
            }
        }
        2 => {
            let size = u64::from(u16_le(&first, 0).unwrap_or(0));
            if size < 26 {
                return Err(
                    Diagnostic::malformed("level 2 header shorter than 26 bytes")
                        .at(cur.span(size)),
                );
            }
            let header = cur.bytes(size).await?;
            let exts = parse_ext_inline(&header, 24);
            let (n, d) = path_from(&exts);
            (join(d, n.unwrap_or_default()), compressed)
        }
        _ => {
            return Err(
                Diagnostic::unsupported(format!("LHA header level {level}")).at(cur.span(22))
            );
        }
    };
    cur.skip(data_len);
    let directory = method == "-lhd-";
    if directory && !name.ends_with('/') && !name.is_empty() {
        name.push('/');
    }
    Ok(Some(Member {
        span: cur.since(start),
        level,
        method,
        name,
        original,
        directory,
    }))
}

/// Level 2 extended headers live inside the header: parse them from memory.
fn parse_ext_inline(header: &[u8], at: usize) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut next = usize::from(u16_le(header, at).unwrap_or(0));
    let mut pos = at.saturating_add(2);
    while next >= 3 && out.len() < MAX_EXT {
        let Some(h) = header.get(pos..pos.saturating_add(next)) else {
            break;
        };
        let kind = h.first().copied().unwrap_or(0);
        out.push((
            kind,
            h.get(1..h.len().saturating_sub(2))
                .unwrap_or_default()
                .to_vec(),
        ));
        pos = pos.saturating_add(next);
        next = usize::from(u16_le(h, h.len().saturating_sub(2)).unwrap_or(0));
    }
    out
}

fn join(dir: Option<String>, name: String) -> String {
    match dir {
        Some(d) if !d.is_empty() => {
            if d.ends_with('/') {
                format!("{d}{name}")
            } else {
                format!("{d}/{name}")
            }
        }
        _ => name,
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut files = 0u64;
    let mut total = 0u64;
    let mut methods: Vec<String> = Vec::new();
    cx.annotate("LHA archive");
    let mut ended = false;
    while !cur.at_end() {
        let Some(m) = next_member(&mut cur).await? else {
            cx.emit(Node::new("End of archive").span(cur.span(1)));
            cur.skip(1);
            ended = true;
            break;
        };
        files = files.saturating_add(1);
        total = total.saturating_add(m.original);
        if !m.directory && !methods.contains(&m.method) {
            methods.push(m.method.clone());
        }
        let summary = if m.directory {
            "directory".to_owned()
        } else {
            format!("{}, {}", m.method, human_size(m.original))
        };
        cx.push(
            Node::new(m.name)
                .span(m.span)
                .summary(summary)
                .lazy(member, (input, m.span, m.level)),
        )
        .await;
    }
    if !ended {
        cx.diag(Diagnostic::warning("no end-of-archive marker"));
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(file.tail(cur.pos())));
    }
    cx.annotate(format!(
        "LHA archive, {}, {} uncompressed, {}",
        count(files, "file", "files"),
        human_size(total),
        methods.join(" ")
    ));
    Ok(())
}

fn common_fields(r: &mut ByteReader<'_>, level: u8) -> Option<(String, u32)> {
    let method = r.text("Method", 5)?;
    let compressed = r.u32("Compressed size", LE)?;
    r.with(|n| n.summary(human_size(compressed.into())));
    let original = r.u32("Original size", LE)?;
    r.with(|n| n.summary(human_size(original.into())));
    let time = r.u32(
        if level == 2 {
            "Modification time"
        } else {
            "Modification time (DOS)"
        },
        LE,
    )?;
    r.with(|n| {
        if level == 2 {
            n.value(Value::Timestamp {
                unix_seconds: time.into(),
            })
        } else {
            n.value(hex(time.into())).summary(crate::text::dos_datetime(
                u16::try_from(time >> 16).unwrap_or(0),
                u16::try_from(time & 0xffff).unwrap_or(0),
            ))
        }
    });
    let attr = r.u8(if level == 2 { "Reserved" } else { "Attribute" })?;
    r.with(|n| n.value(hex(attr.into())));
    r.u8("Level")?;
    Some((method, compressed))
}

fn os_id(r: &mut ByteReader<'_>) -> Option<u8> {
    let os = r.u8("OS ID")?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: os.into(),
            bits: 8,
            name: crate::value::lookup(OS_ID, os.into()),
        })
    });
    Some(os)
}

/// Decodes one extended header's body into nodes.
fn ext_node(kind: u8, body: &[u8], span: Span) -> Node {
    let name = crate::value::lookup(EXT_TYPES, kind.into())
        .map_or_else(|| format!("Extended header {kind:#04x}"), str::to_owned);
    let mut r = ByteReader::new(body, span.sub(1, to_u64(body.len())));
    let mut node = Node::new(name).span(span);
    match kind {
        0x00 => {
            if let Some(crc) = r.u16("Header CRC-16", LE) {
                r.with(|n| n.value(hex(crc.into())));
            }
        }
        0x01 | 0x3f | 0x52 | 0x53 => {
            let s = String::from_utf8_lossy(body).into_owned();
            node = node.value(text(s));
        }
        0x02 => {
            let d: Vec<u8> = body
                .iter()
                .map(|&b| if b == 0xff { b'/' } else { b })
                .collect();
            node = node.value(text(String::from_utf8_lossy(&d)));
        }
        0x40 => {
            if let Some(a) = r.u16("Attributes", LE) {
                r.with(|n| n.value(hex(a.into())));
            }
        }
        0x41 => {
            for name in ["Creation time", "Modification time", "Access time"] {
                if let Some(t) = r.u64(name, LE) {
                    r.with(|n| {
                        n.value(Value::Timestamp {
                            unix_seconds: crate::text::filetime_to_unix(t),
                        })
                    });
                }
            }
        }
        0x42 => {
            r.u64("Compressed size", LE);
            r.u64("Original size", LE);
        }
        0x50 => {
            if let Some(m) = r.u16("Permissions", LE) {
                node = node.summary(unix_mode(m.into()));
            }
        }
        0x51 => {
            r.u16("Group ID", LE);
            r.u16("User ID", LE);
        }
        0x54 => {
            if let Some(t) = r.u32("Modification time", LE) {
                r.with(|n| {
                    n.value(Value::Timestamp {
                        unix_seconds: t.into(),
                    })
                });
            }
        }
        _ => {}
    }
    let nodes = r.into_nodes();
    if nodes.is_empty() {
        node
    } else {
        node.lazy(emit_nodes, nodes)
    }
}

async fn member(cx: Cx, (input, span, level): (Input, Span, u8)) -> Result<()> {
    let first = cx.read(span.sub(0, 2)).await?;
    let header_len = match level {
        2 => u64::from(u16_le(&first, 0).unwrap_or(0)),
        _ => u64::from(first.first().copied().unwrap_or(0)).saturating_add(2),
    };
    let header_span = span.sub(0, header_len);
    let header = cx.read(header_span).await?;
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::malformed("truncated header").at(header_span);
    let mut ext = Vec::new();
    let (method, compressed) = if level == 2 {
        r.u16("Header size", LE).ok_or_else(bad)?;
        let (method, compressed) = common_fields(&mut r, level).ok_or_else(bad)?;
        r.u16("CRC-16", LE).ok_or_else(bad)?;
        r.with(|n| n.value(hex(u16_le(&header, 21).unwrap_or(0).into())));
        os_id(&mut r).ok_or_else(bad)?;
        r.u16("Next header size", LE).ok_or_else(bad)?;
        let mut pos = r.at;
        for (kind, body) in parse_ext_inline(&header, 24) {
            let len = body.len().saturating_add(3);
            ext.push(ext_node(
                kind,
                &body,
                header_span.sub(to_u64(pos), to_u64(len)),
            ));
            pos = pos.saturating_add(len);
        }
        (method, u64::from(compressed))
    } else {
        r.u8("Header size").ok_or_else(bad)?;
        let sum = r.u8("Header checksum").ok_or_else(bad)?;
        let computed = header
            .get(2..)
            .unwrap_or_default()
            .iter()
            .fold(0u8, |a, &b| a.wrapping_add(b));
        r.with(|n| {
            let n = n.value(hex(sum.into()));
            if computed == sum {
                n.summary("valid")
            } else {
                n.diag(Diagnostic::warning(format!(
                    "checksum mismatch: computed {computed:#04x}"
                )))
            }
        });
        let (method, compressed) = common_fields(&mut r, level).ok_or_else(bad)?;
        let name_len = r.u8("Name length").ok_or_else(bad)?;
        r.text("Name", name_len.into()).ok_or_else(bad)?;
        let crc = r.u16("CRC-16", LE).ok_or_else(bad)?;
        r.with(|n| n.value(hex(crc.into())));
        if level == 1 {
            os_id(&mut r).ok_or_else(bad)?;
            r.u16("Next header size", LE).ok_or_else(bad)?;
        } else if r.remaining() > 0 {
            r.bytes("Extended area", to_u64(r.remaining()));
        }
        (method, u64::from(compressed))
    };
    let mut data_at = header_len;
    let mut data_len = compressed;
    if level == 1 {
        let mut cur = Cursor::new(&cx, span, LE);
        cur.seek(header_len);
        let next = u16_le(&header, to_usize(header_len.saturating_sub(2))).unwrap_or(0);
        let (exts, total) = ext_headers(&mut cur, next).await?;
        let mut pos = header_len;
        for (kind, body) in exts {
            let len = to_u64(body.len()).saturating_add(3);
            ext.push(ext_node(kind, &body, span.sub(pos, len)));
            pos = pos.saturating_add(len);
        }
        data_at = pos;
        data_len = data_len.saturating_sub(total);
    }
    cx.emit(
        Node::new(format!("Header (level {level})"))
            .span(header_span)
            .lazy(emit_nodes, r.into_nodes()),
    );
    for node in ext {
        cx.emit(node);
    }
    if method == "-lhd-" {
        return Ok(());
    }
    let data = span.sub(data_at, data_len);
    let node = if stored(&method) {
        embedded("Content", input.nested(data)).summary(human_size(data_len))
    } else {
        unsupported("Compressed data", data, &format!("LHA {method}"))
    };
    cx.emit(crate::formats::util::arcutil::check_len(
        node, data, data_len,
    ));
    Ok(())
}
