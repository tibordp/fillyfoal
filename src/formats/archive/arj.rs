//! ARJ archives.
//!
//! A sequence of headers, each `0x60 0xEA`, a basic header size, the basic
//! header (fixed fields, file name, comment), its CRC-32, and extended
//! headers; the first is the main (archive) header, a size of zero ends the
//! archive. File headers are followed by their compressed data. Stored
//! members are dissected in place; methods 1 to 3 (LZSS with static
//! Huffman blocks, LHA's `-lh6-` family) and 4 (LZSS with unary-coded
//! numbers) are decoded (see [`crate::codec::lzh`]) and their CRC-32
//! checked. Garbled (encrypted) members are unsupported leaves.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::codec::{Codec, crc32, lzh};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{ByteReader, count, emit_nodes, hex, human_size, unsupported};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const MAX_BASIC: u16 = 2600;

pub static FORMAT: Format = Format {
    name: "arj",
    title: "ARJ archive",
    extensions: &["arj"],
    mime: "application/x-arj",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x60\xea")
        && u16_le(h.data, 2).is_some_and(|s| (30..=MAX_BASIC).contains(&s))
        && h.data.get(4).is_some_and(|&f| (30..=64).contains(&f))
        && h.data.get(10) == Some(&2)
}

const HOST_OS: EnumTable = &[
    (0, "MS-DOS"),
    (1, "PRIMOS"),
    (2, "Unix"),
    (3, "Amiga"),
    (4, "Mac OS"),
    (5, "OS/2"),
    (6, "Apple GS"),
    (7, "Atari ST"),
    (8, "NeXT"),
    (9, "VAX VMS"),
    (10, "Windows 95"),
    (11, "Win32"),
];

const FLAGS: FlagTable = &[
    flag(0x01, "GARBLED"),
    flag(0x02, "OLD_SECURED"),
    flag(0x04, "VOLUME"),
    flag(0x08, "EXTFILE"),
    flag(0x10, "PATHSYM"),
    flag(0x20, "BACKUP"),
    flag(0x40, "SECURED"),
    flag(0x80, "ALTNAME"),
];

const METHOD: EnumTable = &[
    (0, "stored"),
    (1, "compressed most"),
    (2, "compressed medium"),
    (3, "compressed fast"),
    (4, "compressed fastest"),
];

const FILE_TYPE: EnumTable = &[
    (0, "binary"),
    (1, "7-bit text"),
    (2, "main header"),
    (3, "directory"),
    (4, "volume label"),
    (5, "chapter label"),
];

/// One header and its data, as found by the walk.
struct Entry {
    span: Span,
    name: String,
    file_type: u8,
    original: u32,
    end: bool,
}

async fn next_entry(cx: &Cx, cur: &mut Cursor<'_>) -> Result<Entry> {
    let start = cur.pos();
    let id = cur.bytes(2).await?;
    if id != [0x60, 0xea] {
        return Err(Diagnostic::malformed("missing header ID 0x60 0xEA").at(cur.since(start)));
    }
    let size = cur.u16().await?;
    if size == 0 {
        return Ok(Entry {
            span: cur.since(start),
            name: String::new(),
            file_type: 0,
            original: 0,
            end: true,
        });
    }
    if size > MAX_BASIC {
        return Err(Diagnostic::malformed(format!("basic header size {size}")).at(cur.since(start)));
    }
    let basic = cur.bytes(size.into()).await?;
    cur.skip(4); // CRC
    // Extended headers: size, data, CRC; a zero size ends them.
    loop {
        let ext = cur.u16().await?;
        if ext == 0 {
            break;
        }
        cur.skip(u64::from(ext).saturating_add(4));
        cx.checkpoint().await;
    }
    let first = usize::from(basic.first().copied().unwrap_or(30));
    let file_type = basic.get(6).copied().unwrap_or(0);
    let compressed = u32_le(&basic, 12).unwrap_or(0);
    let original = u32_le(&basic, 16).unwrap_or(0);
    let name = crate::text::until_nul(basic.get(first..).unwrap_or_default());
    if file_type != 2 {
        cur.skip(compressed.into());
    }
    Ok(Entry {
        span: cur.since(start),
        name,
        file_type,
        original,
        end: false,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut files = 0u64;
    let mut total = 0u64;
    let mut archive = String::new();
    cx.annotate("ARJ archive");
    while cur.remaining() >= 4 {
        let e = next_entry(&cx, &mut cur).await?;
        if e.end {
            cx.emit(Node::new("End of archive").span(e.span));
            break;
        }
        let (name, summary) = match e.file_type {
            2 => {
                archive.clone_from(&e.name);
                ("Main header".to_owned(), e.name.clone())
            }
            3 => {
                files = files.saturating_add(1);
                (e.name.clone(), "directory".to_owned())
            }
            _ => {
                files = files.saturating_add(1);
                total = total.saturating_add(e.original.into());
                (e.name.clone(), human_size(e.original.into()))
            }
        };
        cx.push(
            Node::new(name)
                .span(e.span)
                .summary(summary)
                .lazy(entry, (input, e.span)),
        )
        .await;
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(file.tail(cur.pos())));
    }
    let mut summary = format!(
        "ARJ archive, {}, {} uncompressed",
        count(files, "file", "files"),
        human_size(total)
    );
    if !archive.is_empty() {
        summary = format!("{summary} ({archive})");
    }
    cx.annotate(summary);
    Ok(())
}

fn basic_header(r: &mut ByteReader<'_>, main: bool) -> Option<(u8, u32, usize)> {
    let first = r.u8("First header size")?;
    r.u8("Archiver version")?;
    r.u8("Minimum version to extract")?;
    let os = r.u8("Host OS")?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: os.into(),
            bits: 8,
            name: crate::value::lookup(HOST_OS, os.into()),
        })
    });
    let flags = r.u8("Flags")?;
    r.with(|n| {
        let (set, unknown) = crate::value::decode_flags(FLAGS, flags.into());
        n.value(Value::Flags {
            raw: flags.into(),
            bits: 8,
            set,
            unknown,
        })
    });
    let method = r.u8("Method")?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: method.into(),
            bits: 8,
            name: crate::value::lookup(METHOD, method.into()),
        })
    });
    let kind = r.u8("File type")?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: kind.into(),
            bits: 8,
            name: crate::value::lookup(FILE_TYPE, kind.into()),
        })
    });
    r.u8("Reserved")?;
    let time = r.u32(
        if main {
            "Creation time (DOS)"
        } else {
            "Modification time (DOS)"
        },
        LE,
    )?;
    r.with(|n| {
        n.value(hex(time.into())).summary(crate::text::dos_datetime(
            u16::try_from(time >> 16).unwrap_or(0),
            u16::try_from(time & 0xffff).unwrap_or(0),
        ))
    });
    let compressed = r.u32(
        if main {
            "Archive size"
        } else {
            "Compressed size"
        },
        LE,
    )?;
    r.u32(
        if main {
            "Security envelope position"
        } else {
            "Original size"
        },
        LE,
    )?;
    let crc = r.u32(
        if main {
            "File spec position"
        } else {
            "File CRC-32"
        },
        LE,
    )?;
    if !main {
        r.with(|n| n.value(hex(crc.into())));
    }
    r.u16("Entry name position", LE)?;
    let mode = r.u16("File access mode", LE)?;
    r.with(|n| n.value(hex(mode.into())));
    r.u8("First chapter")?;
    r.u8("Last chapter")?;
    let fixed_end = usize::from(first);
    if fixed_end > r.at {
        let n = to_u64(fixed_end.saturating_sub(r.at));
        r.bytes("Extra data", n)?;
    }
    Some((method, compressed, fixed_end))
}

async fn entry(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let head = cx.read(span.sub(0, 4)).await?;
    let size = u16_le(&head, 2).unwrap_or(0);
    let header_span = span.sub(0, 4u64.saturating_add(size.into()).saturating_add(4));
    let header = cx.read(header_span).await?;
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::malformed("truncated header").at(header_span);
    r.u16("Header ID", LE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(0xea60)));
    r.u16("Basic header size", LE).ok_or_else(bad)?;
    let kind = header.get(4 + 6).copied().unwrap_or(0);
    let main = kind == 2;
    let (method, compressed, _) = basic_header(&mut r, main).ok_or_else(bad)?;
    let names_end = 4usize.saturating_add(size.into());
    let rest = header.get(r.at..names_end).unwrap_or_default();
    let name_len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    r.text("File name", to_u64(name_len)).ok_or_else(bad)?;
    r.skip(1);
    let rest = header.get(r.at..names_end).unwrap_or_default();
    let comment_len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    if comment_len > 0 {
        r.text("Comment", to_u64(comment_len)).ok_or_else(bad)?;
    }
    r.at = names_end;
    let stored = r.u32("Header CRC-32", LE).ok_or_else(bad)?;
    let computed = crc32(header.get(4..names_end).unwrap_or_default());
    r.with(|n| {
        let n = n.value(hex(stored.into()));
        if computed == stored {
            n.summary("valid")
        } else {
            n.diag(Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#010x}"
            )))
        }
    });
    let nodes = r.into_nodes();
    cx.emit(
        Node::new(if main { "Main header" } else { "Local header" })
            .span(header_span)
            .lazy(emit_nodes, nodes),
    );
    // Extended headers.
    let mut cur = Cursor::new(&cx, span, LE);
    cur.seek(header_span.len);
    let mut index = 0u32;
    loop {
        let start = cur.pos();
        let ext = cur.u16().await?;
        if ext == 0 {
            break;
        }
        cur.skip(u64::from(ext).saturating_add(4));
        cx.emit(
            Node::new(format!("Extended header {index}"))
                .span(cur.since(start))
                .summary(human_size(ext.into())),
        );
        index = index.saturating_add(1);
    }
    cx.emit(Node::new("End of extended headers").span(span.sub(cur.pos().saturating_sub(2), 2)));
    if main || kind == 3 {
        return Ok(());
    }
    let data = span.sub(cur.pos(), compressed.into());
    let flags = header.get(8).copied().unwrap_or(0);
    let node = if flags & 0x01 != 0 {
        Node::new("Encrypted data")
            .span(data)
            .diag(Diagnostic::unsupported("garbled (encrypted) file"))
    } else if method == 0 {
        embedded("Content", input.nested(data)).summary(human_size(data.len))
    } else if let 1..=4 = method {
        let original = u64::from(u32_le(&header, 20).unwrap_or(0));
        let crc = u32_le(&header, 24).unwrap_or(0);
        let m = if method == 4 {
            lzh::Method::ArjFastest
        } else {
            lzh::Method::Arj
        };
        let codec = Codec::Lzh(lzh::Params::new(m, Some(original), lzh::Check::Crc32(crc)));
        crate::formats::content("Content", input, data, codec, Some(original))
            .summary(format!("{}, method {method}", human_size(original)))
    } else {
        let m = crate::value::lookup(METHOD, method.into()).unwrap_or("unknown method");
        unsupported(
            "Compressed data",
            data,
            &format!("ARJ method {method} ({m})"),
        )
    };
    cx.emit(crate::formats::util::arcutil::check_len(
        node,
        data,
        compressed.into(),
    ));
    Ok(())
}
