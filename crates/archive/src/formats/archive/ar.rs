//! Unix `ar` archives (static libraries, Debian packages).
//!
//! `!<arch>\n`, then members: a 60-byte text header and the data, padded to
//! an even length. Long names are kept in a `//` member (GNU, referenced as
//! `/offset`) or in front of the data (BSD, `#1/length`). Symbol tables are
//! the `/` (GNU), `/SYM64/` and `__.SYMDEF` (BSD) members. Microsoft
//! libraries (`.lib`) follow the first `/` with a second one in their own
//! little-endian layout (PE/COFF specification, "Second Linker Member").

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_be, u32_le, u64_be, u64_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{Num, ascii_num, parse_ascii};
use crate::formats::util::fmt;
use crate::formats::util::fmt::count;
use crate::formats::util::val::{hex, text};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;

const HEADER: u64 = 60;
const MAX_NAMES: u64 = 16 << 20;
/// The longest name looked up in a name table or symbol string table (as
/// for BSD `#1/` names): an unterminated table must not be scanned to its
/// end once per member or symbol.
const MAX_NAME: usize = 4096;

pub static FORMAT: Format = Format {
    name: "ar",
    title: "ar archive",
    extensions: &["a", "ar", "lib", "rlib"],
    mime: "application/x-archive",
    probe: Probe::Magic(&[(0, b"!<arch>\n")]),
    dissect: crate::expander!(dissect: Input),
};

pub static DEB: Format = Format {
    name: "deb",
    title: "Debian package",
    extensions: &["deb", "udeb", "ipk"],
    mime: "application/vnd.debian.binary-package",
    probe: Probe::Magic(&[(0, b"!<arch>\ndebian-binary   ")]),
    dissect: crate::expander!(dissect: Input),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    File,
    /// GNU `/` or `/SYM64/`, BSD `__.SYMDEF*`.
    Symbols {
        wide: bool,
        bsd: bool,
    },
    /// GNU `//`.
    Names,
    /// Microsoft's second linker member: a `/` right after the first.
    MsSymbols,
}

struct Member {
    span: Span,
    name: String,
    /// Where the content starts and how long it is (BSD names come first).
    data: Span,
    kind: Kind,
}

fn trim_name(raw: &str) -> &str {
    raw.trim_end_matches(' ')
}

/// Reads one member header at the cursor and resolves its name. `prev` is
/// the kind of the member before it, if any.
async fn next_member(
    cx: &Cx,
    cur: &mut Cursor<'_>,
    names: Option<&[u8]>,
    prev: Option<Kind>,
) -> Result<Member> {
    let start = cur.pos();
    let header = cur.bytes(HEADER).await?;
    if header.get(58..60) != Some(b"`\n") {
        return Err(Diagnostic::malformed("bad member header terminator").at(cur.since(start)));
    }
    let raw_name = String::from_utf8_lossy(header.get(..16).unwrap_or_default()).into_owned();
    let raw_name = trim_name(&raw_name).to_owned();
    let size = parse_ascii(header.get(48..58).unwrap_or_default(), 10)
        .ok_or_else(|| Diagnostic::malformed("bad member size").at(cur.since(start)))?;
    let body = cur.span(size);
    cur.skip(size.saturating_add(size & 1));
    let span = cur.since(start);
    let mut data = body;
    let mut kind = Kind::File;
    let name = if let Some(len) = raw_name.strip_prefix("#1/") {
        // BSD: the name is the first `len` bytes of the data.
        let len = len.trim().parse::<u64>().unwrap_or(0).min(size);
        let bytes = cx.read_avail(body.sub(0, len.min(4096))).await?;
        data = body.tail(len);
        crate::text::until_nul(&bytes)
    } else if raw_name == "/"
        && prev
            == Some(Kind::Symbols {
                wide: false,
                bsd: false,
            })
    {
        kind = Kind::MsSymbols;
        raw_name.clone()
    } else if raw_name == "/" || raw_name == "/SYM64/" {
        kind = Kind::Symbols {
            wide: raw_name == "/SYM64/",
            bsd: false,
        };
        raw_name.clone()
    } else if raw_name == "//" {
        kind = Kind::Names;
        raw_name.clone()
    } else if let Some(offset) = raw_name
        .strip_prefix('/')
        .and_then(|o| o.parse::<usize>().ok())
    {
        match names.and_then(|n| n.get(offset..)) {
            Some(rest) => {
                let rest = rest.get(..MAX_NAME).unwrap_or(rest);
                let end = rest
                    .iter()
                    .position(|&b| b == b'\n' || b == 0)
                    .unwrap_or(rest.len());
                let name = String::from_utf8_lossy(rest.get(..end).unwrap_or_default());
                name.strip_suffix('/').unwrap_or(&name).to_owned()
            }
            None => raw_name.clone(),
        }
    } else {
        raw_name.strip_suffix('/').unwrap_or(&raw_name).to_owned()
    };
    if name.starts_with("__.SYMDEF") {
        kind = Kind::Symbols {
            wide: name.contains("_64"),
            bsd: true,
        };
    }
    Ok(Member {
        span,
        name,
        data,
        kind,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 8))
            .value(text("!<arch>")),
    );
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    cur.seek(8);
    let mut names: Option<Arc<Vec<u8>>> = None;
    let mut members = 0u64;
    let mut deb_version = None;
    let mut symbols = false;
    let mut prev = None;
    while cur.remaining() >= HEADER {
        let m = next_member(&cx, &mut cur, names.as_deref().map(Vec::as_slice), prev).await?;
        prev = Some(m.kind);
        let mut node = Node::new(m.name.clone())
            .span(m.span)
            .lazy(member, (input, m.span, m.name.clone(), m.kind));
        node = crate::formats::util::arcutil::check_len(node, m.data, m.data.len);
        node = match m.kind {
            Kind::Names => {
                if m.data.len <= MAX_NAMES {
                    names = Some(Arc::new(cx.read_avail(m.data).await?));
                }
                node.summary("long name table")
            }
            Kind::Symbols { .. } => {
                symbols = true;
                node.summary("symbol table")
            }
            Kind::MsSymbols => node.summary("symbol table (Microsoft second linker member)"),
            Kind::File => {
                members = members.saturating_add(1);
                if m.name == "debian-binary" {
                    let v = cx.read_avail(m.data.sub(0, 16)).await?;
                    deb_version = Some(String::from_utf8_lossy(&v).trim().to_owned());
                }
                node.summary(fmt::size(m.data.len))
            }
        };
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        cx.push(node).await;
    }
    if !cur.at_end() {
        cx.emit(
            Node::new("Trailing data")
                .span(file.tail(cur.pos()))
                .diag(Diagnostic::malformed("not a member header")),
        );
    }
    let summary = match deb_version {
        Some(v) => format!(
            "Debian package, format {v}, {}",
            count(members, "member", "members")
        ),
        None => {
            let mut s = format!("ar archive, {}", count(members, "member", "members"));
            if symbols {
                s.push_str(", with symbol table");
            }
            s
        }
    };
    cx.annotate(summary);
    Ok(())
}

fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Name", 16).emit()?;
    ascii_num(f, "Modification time", 12, 10, Num::Time).emit()?;
    ascii_num(f, "Owner ID", 6, 10, Num::Dec).emit()?;
    ascii_num(f, "Group ID", 6, 10, Num::Dec).emit()?;
    ascii_num(f, "Mode", 8, 8, Num::ModeOf(0o100_000)).emit()?;
    ascii_num(f, "Size", 10, 10, Num::Dec)
        .with(|&s, n| match s {
            Some(s) => n.summary(fmt::size(s)),
            None => n,
        })
        .emit()?;
    f.bytes("Terminator", 2)
        .check(|t| (t != b"`\n").then(|| Diagnostic::malformed("expected \"`\\n\"")))
        .emit()?;
    Ok(())
}

async fn member(cx: Cx, (input, span, name, kind): (Input, Span, String, Kind)) -> Result<()> {
    cx.emit(struct_node(
        "Header",
        span.sub(0, HEADER),
        Endian::Little,
        (),
        header_layout,
    ));
    let mut cur = Cursor::new(&cx, span, Endian::Little);
    let m = next_member(&cx, &mut cur, None, None).await?;
    let header_name = cx.read(span.sub(0, 16)).await?;
    let data = m.data;
    if header_name.starts_with(b"#1/") {
        let name_span = span.sub(
            HEADER,
            m.data
                .offset
                .saturating_sub(span.offset.saturating_add(HEADER)),
        );
        cx.emit(
            Node::new("Long name")
                .span(name_span)
                .value(text(name.clone())),
        );
    }
    match kind {
        Kind::MsSymbols => {
            cx.emit(
                Node::new("Symbols")
                    .span(data)
                    .lazy(ms_symbol_table, (data, input.span)),
            );
        }
        Kind::Names => {
            cx.emit(Node::new("Names").span(data).lazy(long_names, data));
        }
        Kind::Symbols { wide, bsd } => {
            cx.emit(
                Node::new("Symbols")
                    .span(data)
                    .lazy(symbol_table, (data, wide, bsd, input.span)),
            );
        }
        Kind::File => {
            if data.len > 0 {
                cx.emit(embedded("Content", input.nested(data)).summary(fmt::size(data.len)));
            }
        }
    }
    let pad = span.end().saturating_sub(m.data.end());
    if pad > 0 {
        cx.emit(Node::new("Padding").span(span.tail(span.len.saturating_sub(pad))));
    }
    Ok(())
}

async fn long_names(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span.sub(0, MAX_NAMES)).await?;
    let mut at = 0usize;
    let mut lines = 0u32;
    while at < data.len() {
        // Empty names are not pushed, so a table of them needs its own
        // suspension points.
        lines = lines.wrapping_add(1);
        if lines.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        let rest = data.get(at..).unwrap_or_default();
        let len = rest
            .iter()
            .position(|&b| b == b'\n')
            .map_or(rest.len(), |p| p.saturating_add(1));
        let raw = String::from_utf8_lossy(rest.get(..len).unwrap_or_default());
        let name = raw.trim_end_matches(['\n', '/', '\0']).to_owned();
        if !name.is_empty() {
            cx.push(
                Node::new(format!("/{at}"))
                    .span(span.sub(to_u64(at), to_u64(len)))
                    .value(text(name)),
            )
            .await;
        }
        at = at.saturating_add(len.max(1));
    }
    Ok(())
}

/// GNU: count, member offsets (big-endian), NUL-terminated names. BSD:
/// size of the ranlib array, (name offset, member offset) pairs, size of
/// the string table, strings (little-endian on all current systems).
async fn symbol_table(cx: Cx, (span, wide, bsd, file): (Span, bool, bool, Span)) -> Result<()> {
    let data = cx.read(span.sub(0, cx.limits().max_read)).await?;
    let word = if wide { 8usize } else { 4 };
    let get = |at: usize| -> Option<u64> {
        match (wide, bsd) {
            (false, false) => u32_be(&data, at).map(u64::from),
            (true, false) => u64_be(&data, at),
            (false, true) => u32_le(&data, at).map(u64::from),
            (true, true) => u64_le(&data, at),
        }
    };
    let bad = || Diagnostic::malformed("bad symbol table").at(span);
    if bsd {
        let ranlib_len = to_usize(get(0).ok_or_else(bad)?);
        let entries = ranlib_len.checked_div(word.saturating_mul(2)).unwrap_or(0);
        let strtab_at = word.saturating_add(ranlib_len);
        let strtab_len = to_usize(get(strtab_at).ok_or_else(bad)?);
        let strtab_start = strtab_at.saturating_add(word);
        let strtab = data
            .get(strtab_start..strtab_start.saturating_add(strtab_len))
            .ok_or_else(bad)?;
        cx.emit(
            Node::new("Ranlib size")
                .span(span.sub(0, to_u64(word)))
                .value(crate::formats::util::val::uint(to_u64(ranlib_len), 64))
                .summary(count(to_u64(entries), "symbol", "symbols")),
        );
        for i in 0..entries {
            let at = word.saturating_add(i.saturating_mul(word).saturating_mul(2));
            let strx = to_usize(get(at).ok_or_else(bad)?);
            let offset = get(at.saturating_add(word)).ok_or_else(bad)?;
            let rest = strtab.get(strx..).unwrap_or_default();
            let name = crate::text::until_nul(rest.get(..MAX_NAME).unwrap_or(rest));
            cx.push(symbol(
                name,
                span.sub(to_u64(at), to_u64(word.saturating_mul(2))),
                offset,
                file,
            ))
            .await;
        }
        return Ok(());
    }
    let n = to_usize(get(0).ok_or_else(bad)?);
    if n > data.len().checked_div(word).unwrap_or(0) {
        return Err(bad());
    }
    cx.emit(
        Node::new("Symbol count")
            .span(span.sub(0, to_u64(word)))
            .value(crate::formats::util::val::uint(to_u64(n), 64)),
    );
    let mut name_at = word.saturating_add(n.saturating_mul(word));
    for i in 0..n {
        let at = word.saturating_add(i.saturating_mul(word));
        let offset = get(at).ok_or_else(bad)?;
        let rest = data.get(name_at..).unwrap_or_default();
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let name = String::from_utf8_lossy(rest.get(..len).unwrap_or_default()).into_owned();
        name_at = name_at.saturating_add(len).saturating_add(1);
        cx.push(symbol(
            name,
            span.sub(to_u64(at), to_u64(word)),
            offset,
            file,
        ))
        .await;
    }
    Ok(())
}

/// Microsoft's second linker member, little-endian: the member count, the
/// member header offsets (ascending), the symbol count, one 16-bit 1-based
/// index into the offsets per symbol, then the symbol names, NUL-terminated
/// and sorted.
async fn ms_symbol_table(cx: Cx, (span, file): (Span, Span)) -> Result<()> {
    let data = cx.read(span.sub(0, cx.limits().max_read)).await?;
    let bad = || Diagnostic::malformed("bad symbol table").at(span);
    let members = to_usize(u32_le(&data, 0).ok_or_else(bad)?.into());
    if members > data.len().checked_div(4).unwrap_or(0) {
        return Err(bad());
    }
    let offsets_at = 4usize;
    let count_at = offsets_at.saturating_add(members.saturating_mul(4));
    let symbols = to_usize(u32_le(&data, count_at).ok_or_else(bad)?.into());
    let index_at = count_at.saturating_add(4);
    if symbols
        > data
            .len()
            .saturating_sub(index_at)
            .checked_div(2)
            .unwrap_or(0)
    {
        return Err(bad());
    }
    let offsets_span = span.sub(to_u64(offsets_at), to_u64(members.saturating_mul(4)));
    cx.emit(
        Node::new("Member count")
            .span(span.sub(0, 4))
            .value(crate::formats::util::val::uint(to_u64(members), 32)),
    );
    cx.emit(
        Node::new("Member offsets")
            .span(offsets_span)
            .summary(count(to_u64(members), "member", "members"))
            .lazy(ms_offsets, (offsets_span, file)),
    );
    cx.emit(
        Node::new("Symbol count")
            .span(span.sub(to_u64(count_at), 4))
            .value(crate::formats::util::val::uint(to_u64(symbols), 32)),
    );
    let mut name_at = index_at.saturating_add(symbols.saturating_mul(2));
    for i in 0..symbols {
        let at = index_at.saturating_add(i.saturating_mul(2));
        let index = usize::from(crate::bytes::u16_le(&data, at).ok_or_else(bad)?);
        let rest = data.get(name_at..).unwrap_or_default();
        let rest = rest.get(..MAX_NAME).unwrap_or(rest);
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let name = String::from_utf8_lossy(rest.get(..len).unwrap_or_default()).into_owned();
        name_at = name_at.saturating_add(len).saturating_add(1);
        let node_span = span.sub(to_u64(at), 2);
        let offset = index
            .checked_sub(1)
            .filter(|&i| i < members)
            .and_then(|i| u32_le(&data, offsets_at.saturating_add(i.saturating_mul(4))));
        cx.push(match offset {
            Some(offset) => symbol(name, node_span, offset.into(), file),
            None => Node::new(name)
                .span(node_span)
                .value(crate::formats::util::val::uint(to_u64(index), 16))
                .diag(Diagnostic::malformed("member index out of range")),
        })
        .await;
    }
    Ok(())
}

async fn ms_offsets(cx: Cx, (span, file): (Span, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, chunk) in data.as_chunks::<4>().0.iter().enumerate() {
        let offset = u32::from_le_bytes(*chunk);
        cx.push(
            Node::new(format!("Member {}", i.saturating_add(1)))
                .span(span.sub(to_u64(i.saturating_mul(4)), 4))
                .value(hex(offset, 32))
                .summary("member header offset")
                .target(file.sub(offset.into(), HEADER)),
        )
        .await;
    }
    Ok(())
}

fn symbol(name: String, span: Span, member: u64, file: Span) -> Node {
    Node::new(name)
        .span(span)
        .value(hex(member, 64))
        .summary("member header offset")
        .target(file.sub(member, HEADER))
}
