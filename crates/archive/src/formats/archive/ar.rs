//! Unix `ar` archives (static libraries, Debian packages).
//!
//! `!<arch>\n`, then members: a 60-byte text header and the data, padded to
//! an even length. Long names are kept in a `//` member (GNU, referenced as
//! `/offset`) or in front of the data (BSD, `#1/length`). Symbol tables are
//! the `/` (GNU), `/SYM64/` and `__.SYMDEF` (BSD) members.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_be, u32_le, u64_be, u64_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{Num, ascii_num, count, hex, human_size, parse_ascii, text};
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

/// Reads one member header at the cursor and resolves its name.
async fn next_member(cx: &Cx, cur: &mut Cursor<'_>, names: Option<&[u8]>) -> Result<Member> {
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
    while cur.remaining() >= HEADER {
        let m = next_member(&cx, &mut cur, names.as_deref().map(Vec::as_slice)).await?;
        let mut node = Node::new(m.name.clone())
            .span(m.span)
            .lazy(member, (input, m.span, m.name.clone()));
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
            Kind::File => {
                members = members.saturating_add(1);
                if m.name == "debian-binary" {
                    let v = cx.read_avail(m.data.sub(0, 16)).await?;
                    deb_version = Some(String::from_utf8_lossy(&v).trim().to_owned());
                }
                node.summary(human_size(m.data.len))
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
    ascii_num(f, "Mode", 8, 8, Num::Mode).emit()?;
    ascii_num(f, "Size", 10, 10, Num::Dec)
        .with(|&s, n| match s {
            Some(s) => n.summary(human_size(s)),
            None => n,
        })
        .emit()?;
    f.bytes("Terminator", 2)
        .check(|t| (t != b"`\n").then(|| Diagnostic::malformed("expected \"`\\n\"")))
        .emit()?;
    Ok(())
}

async fn member(cx: Cx, (input, span, name): (Input, Span, String)) -> Result<()> {
    cx.emit(struct_node(
        "Header",
        span.sub(0, HEADER),
        Endian::Little,
        (),
        header_layout,
    ));
    let mut cur = Cursor::new(&cx, span, Endian::Little);
    let m = next_member(&cx, &mut cur, None).await?;
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
    match m.kind {
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
                cx.emit(embedded("Content", input.nested(data)).summary(human_size(data.len)));
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
                .value(crate::formats::util::arcutil::uint(to_u64(ranlib_len)))
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
            .value(crate::formats::util::arcutil::uint(to_u64(n))),
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

fn symbol(name: String, span: Span, member: u64, file: Span) -> Node {
    Node::new(name)
        .span(span)
        .value(hex(member))
        .summary("member header offset")
        .target(file.sub(member, HEADER))
}
