//! tar archives: v7, POSIX ustar/pax and GNU.
//!
//! An archive is a sequence of 512-byte headers, each followed by its data
//! rounded up to 512 bytes, ended by two zero blocks. Some headers only
//! describe the next one (GNU long names `L`/`K`, pax extended headers `x`);
//! the listing folds them into the member they belong to. Members are listed
//! in pages; a member's headers are decoded when it is expanded, and its
//! content is dissected as an embedded file.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{Num, ascii_num, count, human_size, parse_tar_number, text};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

const BLOCK: u64 = 512;
/// The largest metadata payload (long name, pax header) decoded in memory.
const MAX_META: u64 = 1 << 20;
/// Metadata headers allowed in front of one member.
const MAX_META_CHAIN: usize = 64;

pub static FORMAT: Format = Format {
    name: "tar",
    title: "tar archive",
    extensions: &["tar"],
    mime: "application/x-tar",
    probe: Probe::Magic(&[(257, b"ustar\0"), (257, b"ustar ")]),
    dissect: crate::expander!(dissect: Input),
};

/// Pre-POSIX archives have no magic; recognise them by a valid header
/// checksum and sane numeric fields.
pub static V7: Format = Format {
    name: "tar-v7",
    title: "tar archive (v7)",
    extensions: &["tar"],
    mime: "application/x-tar",
    probe: Probe::Custom(is_v7),
    dissect: crate::expander!(dissect: Input),
};

fn is_v7(h: &Head<'_>) -> bool {
    let Some(block) = h.data.get(..512) else {
        return false;
    };
    let numeric = |at: usize, len: usize| {
        block
            .get(at..at.saturating_add(len))
            .is_some_and(|b| b.iter().all(|&c| matches!(c, b'0'..=b'7' | b' ' | 0)))
    };
    block.first().is_some_and(|&c| c != 0)
        && numeric(100, 24)
        && numeric(124, 12)
        && numeric(136, 12)
        && checksum_ok(block)
}

/// Computes the header checksum (the checksum field counts as spaces) and
/// compares it with the stored one. Some old tars summed signed bytes.
fn checksum_ok(block: &[u8]) -> bool {
    let Some(stored) = block.get(148..156).and_then(parse_tar_number) else {
        return false;
    };
    let (unsigned, signed) = checksums(block);
    stored == unsigned || i64::try_from(stored).ok() == Some(signed)
}

fn checksums(block: &[u8]) -> (u64, i64) {
    let mut unsigned = 0u64;
    let mut signed = 0i64;
    for (i, &b) in block.iter().enumerate().take(512) {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned = unsigned.saturating_add(b.into());
        signed = signed.saturating_add(i64::from(b.cast_signed()));
    }
    (unsigned, signed)
}

const TYPEFLAG: EnumTable = &[
    (0, "regular file (old)"),
    (b'0' as u64, "regular file"),
    (b'1' as u64, "hard link"),
    (b'2' as u64, "symbolic link"),
    (b'3' as u64, "character device"),
    (b'4' as u64, "block device"),
    (b'5' as u64, "directory"),
    (b'6' as u64, "FIFO"),
    (b'7' as u64, "contiguous file"),
    (b'g' as u64, "pax global extended header"),
    (b'x' as u64, "pax extended header"),
    (b'A' as u64, "Solaris ACL"),
    (b'D' as u64, "GNU dump directory"),
    (b'E' as u64, "Solaris extended attributes"),
    (b'I' as u64, "inode metadata"),
    (b'K' as u64, "GNU long link name"),
    (b'L' as u64, "GNU long name"),
    (b'M' as u64, "GNU multi-volume continuation"),
    (b'N' as u64, "GNU long names (old)"),
    (b'S' as u64, "GNU sparse file"),
    (b'V' as u64, "GNU volume label"),
    (b'X' as u64, "Solaris extended header"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    V7,
    Ustar,
    Gnu,
}

impl Flavor {
    fn of(block: &[u8]) -> Flavor {
        match block.get(257..265) {
            Some(b"ustar  \0") => Flavor::Gnu,
            Some(m) if m.starts_with(b"ustar") => Flavor::Ustar,
            _ => Flavor::V7,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Flavor::V7 => "v7",
            Flavor::Ustar => "ustar",
            Flavor::Gnu => "GNU",
        }
    }
}

/// The interesting fields of one raw header block.
struct Raw {
    name: String,
    mode: u64,
    size: u64,
    typeflag: u8,
    linkname: String,
    flavor: Flavor,
    checksum_ok: bool,
    /// GNU sparse: whether extension blocks follow.
    extended: bool,
}

fn raw_header(block: &[u8]) -> Raw {
    let field = |at: usize, len: usize| block.get(at..at.saturating_add(len)).unwrap_or_default();
    let flavor = Flavor::of(block);
    let mut name = crate::text::until_nul(field(0, 100));
    if flavor == Flavor::Ustar {
        let prefix = crate::text::until_nul(field(345, 155));
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
    }
    Raw {
        name,
        mode: parse_tar_number(field(100, 8)).unwrap_or(0),
        size: parse_tar_number(field(124, 12)).unwrap_or(0),
        typeflag: block.get(156).copied().unwrap_or(0),
        linkname: crate::text::until_nul(field(157, 100)),
        flavor,
        checksum_ok: checksum_ok(block),
        extended: flavor == Flavor::Gnu && field(482, 1).first().is_some_and(|&b| b != 0),
    }
}

fn padded(size: u64) -> u64 {
    size.div_ceil(BLOCK).saturating_mul(BLOCK)
}

/// A member: its metadata headers and the main header, as found by a walk.
struct Member {
    /// From the first metadata header to the end of the padded data.
    span: Span,
    name: String,
    linkname: String,
    typeflag: u8,
    mode: u64,
    size: u64,
    bad_checksum: bool,
}

/// Reads the member starting at the cursor. Returns `None` at an end-of-archive
/// (zero) block, leaving the cursor on it.
async fn next_member(cx: &Cx, cur: &mut Cursor<'_>) -> Result<Option<Member>> {
    let start = cur.pos();
    let mut long_name = None;
    let mut long_link = None;
    let mut pax_path = None;
    let mut pax_link = None;
    let mut pax_size = None;
    let mut bad_checksum = false;
    for _ in 0..MAX_META_CHAIN {
        let block = cur.peek(BLOCK).await?;
        if block.iter().all(|&b| b == 0) {
            if cur.pos() == start {
                return Ok(None);
            }
            return Err(
                Diagnostic::malformed("metadata header not followed by a member")
                    .at(cur.since(start)),
            );
        }
        if to_u64(block.len()) < BLOCK {
            return Err(Diagnostic::truncated(cur.span(BLOCK), to_u64(block.len())));
        }
        cur.skip(BLOCK);
        let raw = raw_header(&block);
        bad_checksum |= !raw.checksum_ok;
        let data = cur.span(raw.size);
        match raw.typeflag {
            b'L' | b'K' | b'x' => {
                cur.skip(padded(raw.size));
                if raw.size > MAX_META {
                    continue;
                }
                let bytes = cx.read_avail(data).await?;
                match raw.typeflag {
                    b'L' => long_name = Some(crate::text::until_nul(&bytes)),
                    b'K' => long_link = Some(crate::text::until_nul(&bytes)),
                    _ => {
                        for record in pax_records(&bytes) {
                            match record.key.as_str() {
                                "path" => pax_path = Some(record.value),
                                "linkpath" => pax_link = Some(record.value),
                                "size" => pax_size = record.value.parse().ok(),
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {
                if raw.typeflag == b'S' && raw.extended {
                    skip_sparse_extensions(cur).await?;
                }
                let name = pax_path.or(long_name).unwrap_or(raw.name);
                // v7 marks directories only by a trailing slash.
                let typeflag = match raw.typeflag {
                    0 | b'0' if name.ends_with('/') => b'5',
                    t => t,
                };
                let size = match typeflag {
                    // Links, directories and devices carry no data in ustar,
                    // whatever the size field says.
                    b'1' | b'2' | b'3' | b'4' | b'5' | b'6' => 0,
                    _ => pax_size.unwrap_or(raw.size),
                };
                cur.skip(padded(size));
                return Ok(Some(Member {
                    span: cur.since(start),
                    name,
                    linkname: pax_link.or(long_link).unwrap_or(raw.linkname),
                    typeflag,
                    mode: raw.mode,
                    size,
                    bad_checksum,
                }));
            }
        }
    }
    Err(Diagnostic::limit(format!(
        "more than {MAX_META_CHAIN} metadata headers in a row"
    ))
    .at(cur.since(start)))
}

async fn skip_sparse_extensions(cur: &mut Cursor<'_>) -> Result<()> {
    loop {
        let block = cur.bytes(BLOCK).await?;
        if block.get(504).is_none_or(|&b| b == 0) {
            return Ok(());
        }
    }
}

struct PaxRecord {
    key: String,
    value: String,
    /// Offset and length of the record within the header data.
    at: usize,
    len: usize,
}

/// Parses `"<len> <key>=<value>\n"` records, stopping at the first malformed
/// one.
fn pax_records(data: &[u8]) -> Vec<PaxRecord> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        let rest = data.get(at..).unwrap_or_default();
        let Some(space) = rest.iter().position(|&b| b == b' ') else {
            break;
        };
        let Some(len) = std::str::from_utf8(rest.get(..space).unwrap_or_default())
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        else {
            break;
        };
        let Some(record) = rest.get(..len) else {
            break;
        };
        if len <= space {
            break;
        }
        let body = record
            .get(space.saturating_add(1)..)
            .unwrap_or_default()
            .strip_suffix(b"\n")
            .unwrap_or_default();
        let Some(eq) = body.iter().position(|&b| b == b'=') else {
            break;
        };
        out.push(PaxRecord {
            key: String::from_utf8_lossy(body.get(..eq).unwrap_or_default()).into_owned(),
            value: String::from_utf8_lossy(body.get(eq.saturating_add(1)..).unwrap_or_default())
                .into_owned(),
            at,
            len,
        });
        at = at.saturating_add(len);
    }
    out
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, Endian::Little);
    let first = cur.peek(BLOCK).await?;
    let flavor = Flavor::of(&first);
    cx.annotate(format!("tar archive ({})", flavor.name()));
    // Resume marks: (position, entries so far, their total size).
    let (pos, mut members, mut total) = cx.resume::<(u64, u64, u64)>().unwrap_or((0, 0, 0));
    cur.seek(pos);
    while cur.remaining() >= BLOCK {
        let at = (cur.pos(), members, total);
        cx.mark(move || at);
        let Some(member) = next_member(&cx, &mut cur).await? else {
            break;
        };
        members = members.saturating_add(1);
        total = total.saturating_add(member.size);
        cx.push(member_node(input, &member)).await;
    }
    cx.annotate(format!(
        "tar archive ({}), {}, {}",
        flavor.name(),
        count(members, "entry", "entries"),
        human_size(total)
    ));

    // End-of-archive marker: zero blocks.
    let end_start = cur.pos();
    while cur.remaining() >= BLOCK {
        let block = cur.peek(BLOCK).await?;
        if to_u64(block.len()) < BLOCK || block.iter().any(|&b| b != 0) {
            break;
        }
        cur.skip(BLOCK);
    }
    if cur.pos() > end_start {
        let span = cur.since(end_start);
        let blocks = span.len / BLOCK;
        let mut node = Node::new("End of archive").span(span).summary(count(
            blocks,
            "zero block",
            "zero blocks",
        ));
        if blocks < 2 {
            node = node.diag(Diagnostic::warning("expected two zero blocks"));
        }
        cx.emit(node);
    } else if !cur.at_end() || members > 0 {
        cx.diag(Diagnostic::warning("no end-of-archive marker"));
    }
    if !cur.at_end() {
        let rest = input.span.tail(cur.pos());
        let nonzero = cx
            .read_avail(rest.sub(0, BLOCK))
            .await?
            .iter()
            .any(|&b| b != 0);
        if nonzero {
            cx.emit(embedded("Trailing data", input.nested(rest)).summary(human_size(rest.len)));
        } else {
            cx.emit(
                Node::new("Padding")
                    .span(rest)
                    .summary(human_size(rest.len)),
            );
        }
    }
    Ok(())
}

fn member_node(input: Input, m: &Member) -> Node {
    let kind = match m.typeflag {
        b'5' => "directory".to_owned(),
        b'2' => format!("symlink → {}", m.linkname),
        b'1' => format!("hard link → {}", m.linkname),
        b'3' | b'4' | b'6' => crate::value::lookup(TYPEFLAG, m.typeflag.into())
            .unwrap_or("special")
            .to_owned(),
        b'g' => "pax global header".to_owned(),
        b'V' => "volume label".to_owned(),
        b'S' => format!("sparse file, {} stored", human_size(m.size)),
        _ => human_size(m.size),
    };
    let summary = if m.mode != 0 {
        format!(
            "{kind}, {}",
            crate::formats::util::arcutil::unix_mode(m.mode | type_bits(m.typeflag))
        )
    } else {
        kind
    };
    let name = if m.name.is_empty() && m.typeflag == b'g' {
        "pax global header".to_owned()
    } else {
        m.name.clone()
    };
    let mut node = Node::new(name)
        .span(m.span)
        .summary(summary)
        .lazy(member, (input, m.span));
    if m.bad_checksum {
        node = node.diag(Diagnostic::warning("header checksum mismatch"));
    }
    node
}

/// File type bits for `unix_mode`, from the typeflag (tar modes usually
/// hold permissions only).
fn type_bits(typeflag: u8) -> u64 {
    match typeflag {
        b'5' => 0o040_000,
        b'2' => 0o120_000,
        b'3' => 0o020_000,
        b'4' => 0o060_000,
        b'6' => 0o010_000,
        _ => 0o100_000,
    }
}

/// Expands a member: each header block with its metadata payload, then the
/// content.
async fn member(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, Endian::Little);
    while cur.remaining() >= BLOCK {
        let start = cur.pos();
        let block = cur.bytes(BLOCK).await?;
        let raw = raw_header(&block);
        let header_span = cur.since(start);
        let title = match raw.typeflag {
            b'L' => "GNU long name header",
            b'K' => "GNU long link header",
            b'x' => "pax extended header",
            b'g' => "pax global header",
            _ => "Header",
        };
        let mut header = struct_node(title, header_span, Endian::Little, (), header_layout)
            .summary(raw.flavor.name());
        if !raw.checksum_ok {
            header = header.diag(Diagnostic::warning("header checksum mismatch"));
        }
        cx.emit(header);
        let data = cur.span(raw.size);
        match raw.typeflag {
            b'L' | b'K' => {
                cur.skip(padded(raw.size));
                let bytes = cx.read_avail(data.sub(0, MAX_META)).await?;
                let name = if raw.typeflag == b'L' {
                    "Long name"
                } else {
                    "Long link name"
                };
                cx.emit(
                    Node::new(name)
                        .span(data)
                        .value(text(crate::text::until_nul(&bytes))),
                );
                continue;
            }
            b'x' | b'g' => {
                cur.skip(padded(raw.size));
                cx.emit(
                    Node::new("Extended attributes")
                        .span(data)
                        .lazy(pax_header, data),
                );
                if raw.typeflag == b'x' {
                    continue;
                }
                break;
            }
            b'S' => {
                let mut ext = Vec::new();
                if raw.extended {
                    let ext_start = cur.pos();
                    skip_sparse_extensions(&mut cur).await?;
                    ext.push(cur.since(ext_start));
                }
                cx.emit(
                    Node::new("Sparse map")
                        .span(header_span.sub(386, 96))
                        .lazy(sparse_map, (header_span, ext.first().copied())),
                );
                let data = cur.span(raw.size);
                cx.emit(
                    Node::new("Sparse data")
                        .span(data)
                        .summary(human_size(raw.size))
                        .diag(Diagnostic::note(
                            "stored fragments of a sparse file; see the sparse map",
                        )),
                );
            }
            b'1' | b'2' | b'3' | b'4' | b'5' | b'6' => {}
            _ => {
                // A preceding pax header may override the size.
                let size = pax_size(&cx, span, start).await?.unwrap_or(raw.size);
                let data = cur.span(size);
                if size > 0 {
                    let node = embedded("Content", input.nested(data)).summary(human_size(size));
                    cx.emit(crate::formats::util::arcutil::check_len(node, data, size));
                }
            }
        }
        break;
    }
    Ok(())
}

/// The `size` record of a pax header in front of the header at `main`.
async fn pax_size(cx: &Cx, member: Span, main: u64) -> Result<Option<u64>> {
    let mut cur = Cursor::new(cx, member, Endian::Little);
    let mut size = None;
    while cur.pos() < main {
        let block = cur.bytes(BLOCK).await?;
        let raw = raw_header(&block);
        let data = cur.span(raw.size);
        cur.skip(padded(raw.size));
        if raw.typeflag == b'x' && raw.size <= MAX_META {
            let bytes = cx.read_avail(data).await?;
            if let Some(r) = pax_records(&bytes).into_iter().find(|r| r.key == "size") {
                size = r.value.parse().ok();
            }
        }
    }
    Ok(size)
}

async fn pax_header(cx: Cx, span: Span) -> Result<()> {
    let bytes = cx.read(span.sub(0, MAX_META)).await?;
    let records = pax_records(&bytes);
    let mut end = 0usize;
    for r in records {
        end = r.at.saturating_add(r.len);
        let record_span = span.sub(to_u64(r.at), to_u64(r.len));
        let mut node = Node::new(r.key.clone())
            .span(record_span)
            .value(text(r.value.clone()));
        node = match r.key.as_str() {
            "mtime" | "atime" | "ctime" | "LIBARCHIVE.creationtime" => node.summary(
                r.value
                    .split('.')
                    .next()
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(|s| {
                        crate::render::value(&crate::value::Value::Timestamp { unix_seconds: s })
                    })
                    .unwrap_or_default(),
            ),
            "size" | "GNU.sparse.realsize" | "GNU.sparse.size" => {
                node.summary(r.value.parse().map(human_size).unwrap_or_default())
            }
            _ => node,
        };
        cx.push(node).await;
    }
    if to_u64(end) < span.len.min(MAX_META) {
        cx.diag(Diagnostic::malformed("malformed pax record").at(span.tail(to_u64(end))));
    }
    Ok(())
}

/// GNU sparse map: (offset, size) pairs in the header and extension blocks.
async fn sparse_map(cx: Cx, (header, ext): (Span, Option<Span>)) -> Result<()> {
    let mut regions = vec![header.sub(386, 96)];
    if let Some(ext) = ext {
        let mut at = 0u64;
        while at < ext.len {
            regions.push(ext.sub(at, 504));
            at = at.saturating_add(BLOCK);
        }
    }
    for region in regions {
        let block = cx.block(region).await?;
        let mut f = Fields::new(&block, Endian::Little);
        while f.remaining() >= 24 {
            let at = f.pos();
            let offset = ascii_num(&mut f, "Offset", 12, 8, Num::Dec).get()?;
            let size = ascii_num(&mut f, "Size", 12, 8, Num::Dec).get()?;
            let (Some(offset), Some(size)) = (offset, size) else {
                break;
            };
            if offset == 0 && size == 0 {
                break;
            }
            cx.push(
                struct_node(
                    "Region",
                    region.sub(at, 24),
                    Endian::Little,
                    (),
                    sparse_entry,
                )
                .summary(format!("{offset:#x}, {}", human_size(size))),
            )
            .await;
        }
    }
    Ok(())
}

fn sparse_entry(f: &mut Fields<'_>, _: &()) -> Result<()> {
    ascii_num(f, "Offset", 12, 8, Num::Hex).emit()?;
    ascii_num(f, "Size", 12, 8, Num::Dec).emit()?;
    Ok(())
}

fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let block = f.block().data.clone();
    let flavor = Flavor::of(&block);
    f.ascii("Name", 100).emit()?;
    ascii_num(f, "Mode", 8, 8, Num::Mode).emit()?;
    ascii_num(f, "UID", 8, 8, Num::Dec).emit()?;
    ascii_num(f, "GID", 8, 8, Num::Dec).emit()?;
    ascii_num(f, "Size", 12, 8, Num::Dec)
        .with(|&v, n| match v {
            Some(v) => n.summary(human_size(v)),
            None => n,
        })
        .emit()?;
    ascii_num(f, "Modification time", 12, 8, Num::Time).emit()?;
    let (unsigned, _) = checksums(&block);
    ascii_num(f, "Checksum", 8, 8, Num::Oct)
        .with(|&v, n| {
            if checksum_ok(&block) {
                n.summary("valid")
            } else if v.is_some() {
                n.diag(Diagnostic::warning(format!(
                    "checksum mismatch: computed 0o{unsigned:o}"
                )))
            } else {
                n
            }
        })
        .emit()?;
    f.u8("Type").enumeration(TYPEFLAG).emit()?;
    f.ascii("Link name", 100).emit()?;
    if flavor == Flavor::V7 {
        return Ok(());
    }
    f.ascii("Magic", 6).emit()?;
    f.ascii("Version", 2).emit()?;
    f.ascii("Owner name", 32).emit()?;
    f.ascii("Group name", 32).emit()?;
    ascii_num(f, "Device major", 8, 8, Num::Dec).emit()?;
    ascii_num(f, "Device minor", 8, 8, Num::Dec).emit()?;
    if flavor == Flavor::Ustar {
        f.ascii("Prefix", 155).emit()?;
        return Ok(());
    }
    ascii_num(f, "Access time", 12, 8, Num::Time).emit()?;
    ascii_num(f, "Change time", 12, 8, Num::Time).emit()?;
    ascii_num(f, "Multi-volume offset", 12, 8, Num::Dec).emit()?;
    f.bytes("Long names (unused)", 4).emit()?;
    f.u8("Unused").emit()?;
    f.skip(96); // sparse map, shown separately
    f.u8("Is extended").emit()?;
    ascii_num(f, "Real size", 12, 8, Num::Dec).emit()?;
    Ok(())
}
