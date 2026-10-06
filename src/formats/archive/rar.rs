//! RAR archives, versions 1.5–4.x and 5.0.
//!
//! Both are a signature followed by blocks, each a header (with a CRC) and
//! an optional data area: RAR 4 headers are fixed little-endian fields, RAR 5
//! headers are built from variable-length integers and carry "extra area"
//! records. Blocks are listed in pages; expanding one decodes its header and
//! shows its data. Stored members are dissected in place; compressed data is
//! an unsupported leaf (see the codec policy).

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::codec::crc32;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{
    ByteReader, count, emit_nodes, hex, human_size, text, unsupported,
};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag};

const LE: Endian = Endian::Little;
const SIG5: &[u8] = b"Rar!\x1a\x07\x01\x00";
/// RAR 5 limits headers to 2 MiB.
const MAX_HEADER5: u64 = 2 << 20;

pub static FORMAT: Format = Format {
    name: "rar",
    title: "RAR archive",
    extensions: &["rar", "cbr"],
    mime: "application/vnd.rar",
    probe: Probe::Magic(&[(0, b"Rar!\x1a\x07\x00"), (0, b"Rar!\x1a\x07\x01\x00")]),
    dissect: crate::expander!(dissect: Input),
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let sig = cx.read_avail(input.span.sub(0, 8)).await?;
    if sig.starts_with(SIG5) {
        dissect5(&cx, input).await
    } else {
        dissect4(&cx, input).await
    }
}

// ---------------------------------------------------------------------------
// RAR 1.5–4.x

const BLOCK4: EnumTable = &[
    (0x72, "marker block"),
    (0x73, "archive header"),
    (0x74, "file header"),
    (0x75, "old comment"),
    (0x76, "old authenticity"),
    (0x77, "old subblock"),
    (0x78, "old recovery record"),
    (0x79, "old authenticity 2"),
    (0x7a, "subblock"),
    (0x7b, "end of archive"),
];

const ARCHIVE_FLAGS4: FlagTable = &[
    flag(0x0001, "VOLUME"),
    flag(0x0002, "COMMENT"),
    flag(0x0004, "LOCK"),
    flag(0x0008, "SOLID"),
    flag(0x0010, "NEW_NUMBERING"),
    flag(0x0020, "AUTHENTICITY"),
    flag(0x0040, "RECOVERY"),
    flag(0x0080, "ENCRYPTED_HEADERS"),
    flag(0x0100, "FIRST_VOLUME"),
    flag(0x8000, "LONG_BLOCK"),
];

const FILE_FLAGS4: FlagTable = &[
    flag(0x0001, "SPLIT_BEFORE"),
    flag(0x0002, "SPLIT_AFTER"),
    flag(0x0004, "PASSWORD"),
    flag(0x0008, "COMMENT"),
    flag(0x0010, "SOLID"),
    field(0x00e0, 0x0000, "DICT_64K"),
    field(0x00e0, 0x0020, "DICT_128K"),
    field(0x00e0, 0x0040, "DICT_256K"),
    field(0x00e0, 0x0060, "DICT_512K"),
    field(0x00e0, 0x0080, "DICT_1M"),
    field(0x00e0, 0x00a0, "DICT_2M"),
    field(0x00e0, 0x00c0, "DICT_4M"),
    field(0x00e0, 0x00e0, "DIRECTORY"),
    flag(0x0100, "LARGE"),
    flag(0x0200, "UNICODE"),
    flag(0x0400, "SALT"),
    flag(0x0800, "VERSION"),
    flag(0x1000, "EXT_TIME"),
    flag(0x8000, "LONG_BLOCK"),
];

const HOST_OS4: EnumTable = &[
    (0, "MS-DOS"),
    (1, "OS/2"),
    (2, "Windows"),
    (3, "Unix"),
    (4, "Mac OS"),
    (5, "BeOS"),
];

const METHOD4: EnumTable = &[
    (0x30, "store"),
    (0x31, "fastest"),
    (0x32, "fast"),
    (0x33, "normal"),
    (0x34, "good"),
    (0x35, "best"),
];

/// What the listing needs from a RAR 4 block.
struct Block4 {
    span: Span,
    kind: u8,
    flags: u16,
    name: Option<String>,
    unpacked: u64,
    crc_ok: bool,
}

/// The NUL-separated ASCII part of a (possibly Unicode-encoded) name.
fn name4(bytes: &[u8]) -> String {
    crate::text::until_nul(bytes)
}

async fn next_block4(cx: &Cx, cur: &mut Cursor<'_>) -> Result<Block4> {
    let start = cur.pos();
    let base = cur.peek(7).await?;
    let (Some(kind), Some(flags), Some(size)) =
        (base.get(2).copied(), u16_le(&base, 3), u16_le(&base, 5))
    else {
        return Err(Diagnostic::truncated(cur.span(7), to_u64(base.len())));
    };
    if size < 7 {
        return Err(Diagnostic::malformed("block header shorter than 7 bytes").at(cur.span(7)));
    }
    let header = cx.read_avail(cur.span(size.into())).await?;
    let long = flags & 0x8000 != 0 || kind == 0x74 || kind == 0x7a;
    let mut add = if long {
        u64::from(u32_le(&header, 7).unwrap_or(0))
    } else {
        0
    };
    let mut name = None;
    let mut unpacked = 0;
    if kind == 0x74 || kind == 0x7a {
        unpacked = u64::from(u32_le(&header, 11).unwrap_or(0));
        let mut name_at = 32usize;
        if flags & 0x100 != 0 {
            let high_pack = u64::from(u32_le(&header, 32).unwrap_or(0));
            let high_unp = u64::from(u32_le(&header, 36).unwrap_or(0));
            add |= high_pack << 32;
            unpacked |= high_unp << 32;
            name_at = 40;
        }
        let len = usize::from(u16_le(&header, 26).unwrap_or(0));
        let bytes = header
            .get(name_at..name_at.saturating_add(len))
            .unwrap_or_default();
        name = Some(name4(bytes));
    }
    let crc_ok = header
        .get(2..)
        .zip(u16_le(&header, 0))
        .is_some_and(|(covered, stored)| (crc32(covered) & 0xffff) as u16 == stored);
    cur.skip(u64::from(size).saturating_add(add));
    Ok(Block4 {
        span: cur.since(start),
        kind,
        flags,
        name,
        unpacked,
        crc_ok,
    })
}

async fn dissect4(cx: &Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 7))
            .value(text("Rar!"))
            .summary("RAR 1.5–4.x"),
    );
    cx.annotate("RAR archive (v4)");
    let mut cur = Cursor::new(cx, file, LE);
    cur.seek(7);
    let mut files = 0u64;
    let mut total = 0u64;
    let mut solid = false;
    let mut encrypted = false;
    while cur.remaining() >= 7 {
        let b = next_block4(cx, &mut cur).await?;
        let kind_name = crate::value::lookup(BLOCK4, b.kind.into()).unwrap_or("unknown block");
        let (name, summary) = match (b.kind, &b.name) {
            (0x74, Some(n)) => {
                files = files.saturating_add(1);
                total = total.saturating_add(b.unpacked);
                let s = if b.flags & 0xe0 == 0xe0 {
                    "directory".to_owned()
                } else {
                    human_size(b.unpacked)
                };
                (n.clone(), s)
            }
            (0x7a, Some(n)) => (format!("Subblock {n}"), human_size(b.span.len)),
            (0x73, _) => {
                solid = b.flags & 0x0008 != 0;
                encrypted = b.flags & 0x0080 != 0;
                ("Archive header".to_owned(), String::new())
            }
            (0x7b, _) => ("End of archive".to_owned(), String::new()),
            _ => (capitalize(kind_name), String::new()),
        };
        let mut node = Node::new(name).span(b.span).lazy(block4, (input, b.span));
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if !b.crc_ok {
            node = node.diag(Diagnostic::warning("header CRC mismatch"));
        }
        cx.push(node).await;
        if b.kind == 0x7b || encrypted {
            break;
        }
    }
    if encrypted {
        cx.diag(Diagnostic::unsupported("encrypted headers"));
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(file.tail(cur.pos())));
    }
    let solid = if solid { "solid, " } else { "" };
    cx.annotate(format!(
        "RAR archive (v4), {solid}{}, {} uncompressed",
        count(files, "file", "files"),
        human_size(total)
    ));
    Ok(())
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

async fn block4(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let base = cx.read(span.sub(0, 7)).await?;
    let size = u16_le(&base, 5).unwrap_or(7);
    let header_span = span.sub(0, size.into());
    let header = cx.read(header_span).await?;
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::malformed("truncated block header").at(header_span);
    let stored_crc = r.u16("Header CRC", LE).ok_or_else(bad)?;
    let computed = (crc32(header.get(2..).unwrap_or_default()) & 0xffff) as u16;
    r.with(|n| {
        let n = n.value(hex(stored_crc.into()));
        if computed == stored_crc {
            n.summary("valid")
        } else {
            n.diag(Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#06x}"
            )))
        }
    });
    let kind = r.u8("Header type").ok_or_else(bad)?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: kind.into(),
            bits: 8,
            name: crate::value::lookup(BLOCK4, kind.into()),
        })
    });
    let flags = r.u16("Flags", LE).ok_or_else(bad)?;
    let table = match kind {
        0x73 => Some(ARCHIVE_FLAGS4),
        0x74 | 0x7a => Some(FILE_FLAGS4),
        _ => None,
    };
    r.with(|n| match table {
        Some(t) => {
            let (set, unknown) = crate::value::decode_flags(t, flags.into());
            n.value(Value::Flags {
                raw: flags.into(),
                bits: 16,
                set,
                unknown,
            })
        }
        None => n.value(hex(flags.into())),
    });
    r.u16("Header size", LE).ok_or_else(bad)?;
    let mut data = None;
    match kind {
        0x73 => {
            r.u16("Reserved 1", LE);
            r.u32("Reserved 2", LE);
        }
        0x74 | 0x7a => {
            let pack = r.u32("Packed size", LE).ok_or_else(bad)?;
            r.with(|n| n.summary(human_size(pack.into())));
            let unp = r.u32("Unpacked size", LE).ok_or_else(bad)?;
            r.with(|n| n.summary(human_size(unp.into())));
            let os = r.u8("Host OS").ok_or_else(bad)?;
            r.with(|n| {
                n.value(Value::Enum {
                    raw: os.into(),
                    bits: 8,
                    name: crate::value::lookup(HOST_OS4, os.into()),
                })
            });
            let crc = r.u32("File CRC", LE).ok_or_else(bad)?;
            r.with(|n| n.value(hex(crc.into())));
            let time = r.u32("Modification time (DOS)", LE).ok_or_else(bad)?;
            r.with(|n| {
                let date = u16::try_from(time >> 16).unwrap_or(0);
                let t = u16::try_from(time & 0xffff).unwrap_or(0);
                n.value(hex(time.into()))
                    .summary(crate::text::dos_datetime(date, t))
            });
            let ver = r.u8("Version needed").ok_or_else(bad)?;
            r.with(|n| n.summary(format!("{}.{}", ver / 10, ver % 10)));
            let method = r.u8("Method").ok_or_else(bad)?;
            r.with(|n| {
                n.value(Value::Enum {
                    raw: method.into(),
                    bits: 8,
                    name: crate::value::lookup(METHOD4, method.into()),
                })
            });
            let name_len = r.u16("Name size", LE).ok_or_else(bad)?;
            let attr = r.u32("Attributes", LE).ok_or_else(bad)?;
            r.with(|n| n.value(hex(attr.into())));
            let mut packed = u64::from(pack);
            if flags & 0x100 != 0 {
                let hp = r.u32("High packed size", LE).ok_or_else(bad)?;
                r.u32("High unpacked size", LE).ok_or_else(bad)?;
                packed |= u64::from(hp) << 32;
            }
            let raw = r.bytes("Name", name_len.into()).ok_or_else(bad)?;
            let name = name4(raw);
            r.with(|n| n.value(text(name.clone())));
            if flags & 0x400 != 0 {
                r.bytes("Salt", 8);
            }
            let data_span = span.sub(size.into(), packed);
            let directory = flags & 0xe0 == 0xe0 && kind == 0x74;
            data = Some(if directory || packed == 0 {
                None
            } else if kind == 0x7a {
                Some(Node::new("Data").span(data_span))
            } else if flags & 0x04 != 0 {
                Some(
                    Node::new("Encrypted data")
                        .span(data_span)
                        .diag(Diagnostic::unsupported("encrypted file")),
                )
            } else if flags & 0x03 != 0 {
                Some(
                    Node::new("Data (split across volumes)")
                        .span(data_span)
                        .diag(Diagnostic::unsupported("multi-volume member")),
                )
            } else if method == 0x30 {
                Some(embedded("Content", input.nested(data_span)).summary(human_size(packed)))
            } else {
                let name = crate::value::lookup(METHOD4, method.into()).unwrap_or("unknown");
                Some(unsupported(
                    "Compressed data",
                    data_span,
                    &format!("RAR {}.{} ({name})", ver / 10, ver % 10),
                ))
            });
        }
        _ => {
            if flags & 0x8000 != 0 {
                let add = r.u32("Data size", LE).ok_or_else(bad)?;
                data = Some(Some(
                    Node::new("Data").span(span.sub(size.into(), add.into())),
                ));
            }
        }
    }
    if r.remaining() > 0 {
        let start = r.at;
        r.skip(to_u64(r.remaining()));
        let rest = r.since(start);
        r.push(Node::new("Extended header data").span(rest));
    }
    let nodes = r.into_nodes();
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .lazy(emit_nodes, nodes),
    );
    if let Some(Some(node)) = data {
        cx.emit(node);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RAR 5.0

const HEADER5: EnumTable = &[
    (1, "main archive header"),
    (2, "file header"),
    (3, "service header"),
    (4, "encryption header"),
    (5, "end of archive"),
];

const COMMON_FLAGS5: FlagTable = &[
    flag(0x01, "EXTRA_AREA"),
    flag(0x02, "DATA_AREA"),
    flag(0x04, "SKIP_IF_UNKNOWN"),
    flag(0x08, "SPLIT_BEFORE"),
    flag(0x10, "SPLIT_AFTER"),
    flag(0x20, "DEPENDS_ON_PRECEDING"),
    flag(0x40, "PRESERVE_CHILD"),
];

const ARCHIVE_FLAGS5: FlagTable = &[
    flag(0x01, "VOLUME"),
    flag(0x02, "VOLUME_NUMBER"),
    flag(0x04, "SOLID"),
    flag(0x08, "RECOVERY"),
    flag(0x10, "LOCKED"),
];

const FILE_FLAGS5: FlagTable = &[
    flag(0x01, "DIRECTORY"),
    flag(0x02, "MTIME"),
    flag(0x04, "CRC32"),
    flag(0x08, "UNKNOWN_SIZE"),
];

const HOST_OS5: EnumTable = &[(0, "Windows"), (1, "Unix")];

const FILE_EXTRA5: EnumTable = &[
    (1, "encryption"),
    (2, "file hash"),
    (3, "file time"),
    (4, "file version"),
    (5, "redirection"),
    (6, "Unix owner"),
    (7, "service data"),
];

const MAIN_EXTRA5: EnumTable = &[(1, "locator"), (2, "metadata")];

/// What the listing needs from a RAR 5 block.
struct Block5 {
    span: Span,
    kind: u64,
    name: Option<String>,
    unpacked: u64,
    directory: bool,
    crc_ok: bool,
}

/// The fields of a RAR 5 file or service header after the common part.
struct FileFields {
    flags: u64,
    unpacked: u64,
    method: u64,
    name: String,
}

fn file_fields(r: &mut ByteReader<'_>) -> Option<FileFields> {
    let flags = r.vint("File flags")?;
    r.with(|n| {
        let (set, unknown) = crate::value::decode_flags(FILE_FLAGS5, flags);
        n.value(Value::Flags {
            raw: flags,
            bits: 64,
            set,
            unknown,
        })
    });
    let unpacked = r.vint("Unpacked size")?;
    r.with(|n| n.summary(human_size(unpacked)));
    let attr = r.vint("Attributes")?;
    r.with(|n| n.value(hex(attr)));
    if flags & 0x02 != 0 {
        let t = r.u32("Modification time", LE)?;
        r.with(|n| {
            n.value(Value::Timestamp {
                unix_seconds: t.into(),
            })
        });
    }
    if flags & 0x04 != 0 {
        let c = r.u32("Data CRC32", LE)?;
        r.with(|n| n.value(hex(c.into())));
    }
    let info = r.vint("Compression information")?;
    r.with(|n| {
        n.value(hex(info)).summary(format!(
            "version {}, method {}{}, dictionary {}",
            info & 0x3f,
            (info >> 7) & 7,
            if info & 0x40 != 0 { ", solid" } else { "" },
            human_size(0x2_0000u64 << ((info >> 10) & 0xf))
        ))
    });
    let os = r.vint("Host OS")?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: os,
            bits: 64,
            name: crate::value::lookup(HOST_OS5, os),
        })
    });
    let len = r.vint("Name length")?;
    let name = r.text("Name", len)?;
    Some(FileFields {
        flags,
        unpacked,
        method: (info >> 7) & 7,
        name,
    })
}

/// The common part of a RAR 5 header: type, flags, extra and data sizes.
struct Common {
    kind: u64,
    flags: u64,
    extra: u64,
    data: u64,
}

fn common5(r: &mut ByteReader<'_>) -> Option<Common> {
    let kind = r.vint("Header type")?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: kind,
            bits: 64,
            name: crate::value::lookup(HEADER5, kind),
        })
    });
    let flags = r.vint("Header flags")?;
    r.with(|n| {
        let (set, unknown) = crate::value::decode_flags(COMMON_FLAGS5, flags);
        n.value(Value::Flags {
            raw: flags,
            bits: 64,
            set,
            unknown,
        })
    });
    let extra = if flags & 0x01 != 0 {
        r.vint("Extra area size")?
    } else {
        0
    };
    let data = if flags & 0x02 != 0 {
        let d = r.vint("Data size")?;
        r.with(|n| n.summary(human_size(d)));
        d
    } else {
        0
    };
    Some(Common {
        kind,
        flags,
        extra,
        data,
    })
}

async fn next_block5(cx: &Cx, cur: &mut Cursor<'_>) -> Result<Block5> {
    let start = cur.pos();
    let head = cur.peek(4 + 3).await?;
    let (size, vlen) = crate::bytes::uleb128(head.get(4..).unwrap_or_default())
        .ok_or_else(|| Diagnostic::malformed("bad header size").at(cur.span(7)))?;
    if size > MAX_HEADER5 || size == 0 {
        return Err(Diagnostic::malformed(format!("header size {size:#x}")).at(cur.span(7)));
    }
    let header_len = 4u64.saturating_add(to_u64(vlen)).saturating_add(size);
    let header_span = cur.span(header_len);
    let header = cx.read(header_span).await?;
    let crc_ok = header
        .get(4..)
        .zip(u32_le(&header, 0))
        .is_some_and(|(covered, stored)| crc32(covered) == stored);
    let mut r = ByteReader::new(&header, header_span);
    r.at = 4usize.saturating_add(vlen);
    let c = common5(&mut r).ok_or_else(|| Diagnostic::malformed("bad header").at(header_span))?;
    let mut name = None;
    let mut unpacked = 0;
    let mut directory = false;
    if (c.kind == 2 || c.kind == 3)
        && let Some(f) = file_fields(&mut r)
    {
        name = Some(f.name);
        unpacked = f.unpacked;
        directory = f.flags & 1 != 0;
    }
    cur.skip(header_len.saturating_add(c.data));
    Ok(Block5 {
        span: cur.since(start),
        kind: c.kind,
        name,
        unpacked,
        directory,
        crc_ok,
    })
}

async fn dissect5(cx: &Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 8))
            .value(text("Rar!"))
            .summary("RAR 5.0"),
    );
    cx.annotate("RAR archive (v5)");
    let mut cur = Cursor::new(cx, file, LE);
    cur.seek(8);
    let mut files = 0u64;
    let mut total = 0u64;
    let mut encrypted = false;
    while cur.remaining() >= 6 {
        let b = next_block5(cx, &mut cur).await?;
        let (name, summary) = match (b.kind, b.name) {
            (2, Some(n)) => {
                files = files.saturating_add(1);
                total = total.saturating_add(b.unpacked);
                let s = if b.directory {
                    "directory".to_owned()
                } else {
                    human_size(b.unpacked)
                };
                (n, s)
            }
            (3, Some(n)) => (format!("Service {n}"), human_size(b.unpacked)),
            (k, _) => (
                capitalize(crate::value::lookup(HEADER5, k).unwrap_or("unknown header")),
                String::new(),
            ),
        };
        let mut node = Node::new(name).span(b.span).lazy(block5, (input, b.span));
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if !b.crc_ok {
            node = node.diag(Diagnostic::warning("header CRC mismatch"));
        }
        cx.push(node).await;
        if b.kind == 4 {
            encrypted = true;
            break;
        }
        if b.kind == 5 {
            break;
        }
    }
    if encrypted {
        cx.emit(
            Node::new("Encrypted headers")
                .span(file.tail(cur.pos()))
                .diag(Diagnostic::unsupported("encrypted archive headers")),
        );
        cx.annotate("RAR archive (v5), encrypted headers");
        return Ok(());
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(file.tail(cur.pos())));
    }
    cx.annotate(format!(
        "RAR archive (v5), {}, {} uncompressed",
        count(files, "file", "files"),
        human_size(total)
    ));
    Ok(())
}

async fn block5(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 7)).await?;
    let (size, vlen) = crate::bytes::uleb128(head.get(4..).unwrap_or_default())
        .ok_or_else(|| Diagnostic::malformed("bad header size").at(span))?;
    let header_len = 4u64.saturating_add(to_u64(vlen)).saturating_add(size);
    let header_span = span.sub(0, header_len);
    let header = cx.read(header_span).await?;
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::malformed("truncated header").at(header_span);
    let stored = r.u32("Header CRC32", LE).ok_or_else(bad)?;
    let computed = crc32(header.get(4..).unwrap_or_default());
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
    r.vint("Header size").ok_or_else(bad)?;
    let c = common5(&mut r).ok_or_else(bad)?;
    let mut fields = None;
    match c.kind {
        1 => {
            let flags = r.vint("Archive flags").ok_or_else(bad)?;
            r.with(|n| {
                let (set, unknown) = crate::value::decode_flags(ARCHIVE_FLAGS5, flags);
                n.value(Value::Flags {
                    raw: flags,
                    bits: 64,
                    set,
                    unknown,
                })
            });
            if flags & 0x02 != 0 {
                r.vint("Volume number").ok_or_else(bad)?;
            }
        }
        2 | 3 => fields = Some(file_fields(&mut r).ok_or_else(bad)?),
        4 => {
            r.vint("Encryption version").ok_or_else(bad)?;
            r.vint("Encryption flags").ok_or_else(bad)?;
            r.u8("KDF count").ok_or_else(bad)?;
            r.bytes("Salt", 16).ok_or_else(bad)?;
        }
        5 => {
            let f = r.vint("End of archive flags").ok_or_else(bad)?;
            r.with(|n| {
                n.summary(if f & 1 != 0 {
                    "not the last volume"
                } else {
                    "last volume"
                })
            });
        }
        _ => {}
    }
    let extra_at = to_usize(header_len.saturating_sub(c.extra));
    let mut encrypted = false;
    if c.extra > 0 && extra_at >= r.at {
        let extra = header.get(extra_at..).unwrap_or_default();
        let extra_span = header_span.sub(to_u64(extra_at), c.extra);
        let records = extra_records(extra, extra_span, c.kind == 1);
        encrypted = records.iter().any(|(t, _)| *t == 1) && c.kind != 1;
        let nodes: Vec<Node> = records.into_iter().map(|(_, n)| n).collect();
        r.at = to_usize(header_len);
        r.push(
            Node::new("Extra area")
                .span(extra_span)
                .summary(count(to_u64(nodes.len()), "record", "records"))
                .lazy(emit_nodes, std::sync::Arc::new(nodes)),
        );
    }
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .lazy(emit_nodes, r.into_nodes()),
    );
    if c.flags & 0x02 != 0 {
        let data = span.sub(header_len, c.data);
        let node = match &fields {
            _ if c.kind == 3 => Node::new("Data").span(data),
            _ if encrypted => Node::new("Encrypted data")
                .span(data)
                .diag(Diagnostic::unsupported("encrypted file")),
            _ if c.flags & 0x18 != 0 => Node::new("Data (split across volumes)")
                .span(data)
                .diag(Diagnostic::unsupported("multi-volume member")),
            Some(f) if f.method == 0 => {
                embedded("Content", input.nested(data)).summary(human_size(data.len))
            }
            Some(f) => unsupported(
                "Compressed data",
                data,
                &format!("RAR 5 (method {})", f.method),
            ),
            None => Node::new("Data").span(data),
        };
        cx.emit(crate::formats::util::arcutil::check_len(node, data, c.data));
    }
    Ok(())
}

/// Extra area records: size, type, data. Returns (type, node) pairs.
fn extra_records(data: &[u8], span: Span, main: bool) -> Vec<(u64, Node)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        let Some((size, l1)) = crate::bytes::uleb128(data.get(at..).unwrap_or_default()) else {
            break;
        };
        let body_at = at.saturating_add(l1);
        let end = body_at.saturating_add(to_usize(size));
        let Some(body) = data.get(body_at..end) else {
            break;
        };
        let record_span = span.sub(to_u64(at), to_u64(end.saturating_sub(at)));
        let mut r = ByteReader::new(body, span.sub(to_u64(body_at), size));
        let kind = r.vint("Type").unwrap_or(0);
        let table = if main { MAIN_EXTRA5 } else { FILE_EXTRA5 };
        r.with(|n| {
            n.value(Value::Enum {
                raw: kind,
                bits: 64,
                name: crate::value::lookup(table, kind),
            })
        });
        if !main && kind == 3 {
            time_record(&mut r);
        } else if !main && kind == 2 {
            r.vint("Hash type");
            r.bytes("BLAKE2sp hash", 32);
        } else if r.remaining() > 0 {
            r.bytes("Data", to_u64(r.remaining()));
        }
        let name = crate::value::lookup(table, kind)
            .map_or_else(|| format!("Record type {kind}"), capitalize);
        out.push((
            kind,
            Node::new(name)
                .span(record_span)
                .lazy(emit_nodes, r.into_nodes()),
        ));
        at = end;
    }
    out
}

fn time_record(r: &mut ByteReader<'_>) -> Option<()> {
    let flags = r.vint("Flags")?;
    let unix = flags & 1 != 0;
    for (bit, name) in [
        (2u64, "Modification time"),
        (4, "Creation time"),
        (8, "Access time"),
    ] {
        if flags & bit == 0 {
            continue;
        }
        if unix {
            let t = r.u32(name, LE)?;
            r.with(|n| {
                n.value(Value::Timestamp {
                    unix_seconds: t.into(),
                })
            });
        } else {
            let t = r.u64(name, LE)?;
            r.with(|n| {
                n.value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(t),
                })
            });
        }
    }
    Some(())
}
