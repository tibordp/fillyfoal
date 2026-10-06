//! `ar` archives: Unix static libraries (`.a`, GNU/System V and BSD
//! variants), Windows `.lib` libraries and import libraries, and thin
//! archives.
//!
//! Members are listed in pages with their names resolved (GNU `//` long
//! name table, `/123` references, BSD `#1/len` names); each member is
//! identified and dissected when expanded (ELF, COFF, Mach-O, COFF short
//! import records, ...). Symbol index members are decoded.

use crate::bytes::{to_u64, to_usize, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::binutil::{ellipsize, text};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;

pub static FORMAT: Format = Format {
    name: "ar",
    title: "ar archive (static or import library)",
    extensions: &["a", "lib", "ar", "rlib"],
    mime: "application/x-archive",
    probe: Probe::Magic(&[(0, b"!<arch>\n"), (0, b"!<thin>\n")]),
    dissect: crate::expander!(dissect: Input),
};

#[derive(Clone, Debug)]
struct Member {
    name: String,
    header: Span,
    data: Span,
    kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// GNU/SysV `/` or Windows first linker member: big-endian offsets.
    SymbolsGnu,
    /// GNU `/SYM64/`: 64-bit big-endian offsets.
    Symbols64,
    /// Windows second linker member: little-endian, sorted.
    SymbolsWindows,
    /// BSD `__.SYMDEF`.
    SymbolsBsd,
    LongNames,
    Regular,
}

fn header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("ar_name", 16).emit()?;
    f.ascii("ar_date", 12)
        .with(|s, n| match s.trim().parse::<i64>() {
            Ok(t) => n.value(crate::value::Value::Timestamp { unix_seconds: t }),
            Err(_) => n,
        })
        .emit()?;
    f.ascii("ar_uid", 6).emit()?;
    f.ascii("ar_gid", 6).emit()?;
    f.ascii("ar_mode", 8).emit()?;
    f.ascii("ar_size", 10).emit()?;
    f.bytes("ar_fmag", 2).emit()?;
    Ok(())
}

fn field(raw: &[u8], at: usize, len: usize) -> String {
    String::from_utf8_lossy(raw.get(at..at.saturating_add(len)).unwrap_or_default())
        .trim_end()
        .to_owned()
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 8)).await?;
    let thin = magic.as_slice() == b"!<thin>\n";
    cx.emit(Node::new("Magic").span(file.sub(0, 8)).value(text(String::from_utf8_lossy(&magic).trim_end().to_owned())));
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    cur.seek(8);
    let mut members = Vec::new();
    let mut long_names: Vec<u8> = Vec::new();
    let mut seen_first_linker = false;
    while cur.remaining() >= 60 {
        let start = cur.pos();
        let raw = cur.bytes(60).await?;
        if raw.get(58..60) != Some(b"`\n") {
            cx.diag(Diagnostic::malformed("bad member header").at(file.sub(start, 60)));
            break;
        }
        let header = file.sub(start, 60);
        let name_field = field(&raw, 0, 16);
        let size: u64 = field(&raw, 48, 10).parse().unwrap_or(0);
        let mut data_start = cur.pos();
        let mut data_len = size;
        let (name, kind) = if name_field == "/" {
            // GNU symbol table; in Windows libraries, the first two
            // linker members are both named "/".
            let k = if seen_first_linker { Kind::SymbolsWindows } else { Kind::SymbolsGnu };
            seen_first_linker = true;
            ("/ (symbol index)".to_owned(), k)
        } else if name_field == "/SYM64/" {
            ("/SYM64/ (symbol index)".to_owned(), Kind::Symbols64)
        } else if name_field == "//" {
            let data = cx.read_avail(file.sub(data_start, size.min(1 << 20))).await?;
            long_names = data;
            ("// (long names)".to_owned(), Kind::LongNames)
        } else if let Some(n) = name_field.strip_prefix("#1/") {
            // BSD: the name is stored at the start of the data.
            let n: u64 = n.trim().parse().unwrap_or(0).min(size);
            let bytes = cx.read_avail(file.sub(data_start, n)).await?;
            data_start = data_start.saturating_add(n);
            data_len = size.saturating_sub(n);
            let name = crate::text::until_nul(&bytes);
            let kind = if name.starts_with("__.SYMDEF") { Kind::SymbolsBsd } else { Kind::Regular };
            (name, kind)
        } else if name_field.starts_with("__.SYMDEF") {
            (name_field.clone(), Kind::SymbolsBsd)
        } else if let Some(Ok(off)) = name_field.strip_prefix('/').map(|n| n.trim().parse::<usize>()) {
            let rest = long_names.get(off..).unwrap_or_default();
            let end = rest.iter().position(|&b| b == b'\n' || b == 0).unwrap_or(rest.len());
            let name = String::from_utf8_lossy(rest.get(..end).unwrap_or_default());
            (name.trim_end_matches('/').to_owned(), Kind::Regular)
        } else if name_field.starts_with('/') && name_field.ends_with('/') && name_field.len() > 2 {
            (name_field.clone(), Kind::LongNames)
        } else {
            (name_field.trim_end_matches('/').to_owned(), Kind::Regular)
        };
        // Thin archives keep member data outside (except index members).
        let stored = if thin && kind == Kind::Regular { 0 } else { size };
        let data = file.sub(data_start, if thin && kind == Kind::Regular { 0 } else { data_len });
        cur.seek(start.saturating_add(60).saturating_add(stored));
        if !cur.pos().is_multiple_of(2) {
            cur.skip(1);
        }
        members.push(Member { name, header, data, kind });
        cx.checkpoint().await;
    }

    // Summary: the kind of archive and, for import libraries, the DLL.
    let regular: Vec<&Member> = members.iter().filter(|m| m.kind == Kind::Regular).collect();
    let mut summary = format!("{} archive, {} members", if thin { "thin ar" } else { "ar" }, regular.len());
    for m in regular.iter().take(16) {
        let head = cx.read_avail(m.data.sub(0, 0x200)).await?;
        if head.starts_with(b"\0\0\xff\xff") && u16_le(&head, 4) == Some(0) {
            let rest = head.get(20..).unwrap_or_default();
            let symbol_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let dll = crate::text::until_nul(rest.get(symbol_end.saturating_add(1)..).unwrap_or_default());
            summary = format!("Windows import library for {dll}, {} members", regular.len());
            break;
        }
    }
    if let Some(m) = members.iter().find(|m| matches!(m.kind, Kind::SymbolsGnu | Kind::SymbolsBsd)) {
        let head = cx.read_avail(m.data.sub(0, 4)).await?;
        let n = if m.kind == Kind::SymbolsGnu {
            u32_be(&head, 0).unwrap_or(0)
        } else {
            u32_le(&head, 0).unwrap_or(0) / 8
        };
        summary.push_str(&format!(", {n} symbols"));
    }
    let names: Vec<&str> = regular.iter().take(8).map(|m| m.name.as_str()).collect();
    if !names.is_empty() {
        summary.push_str(&format!(": {}", ellipsize(&names.join(", "), 100)));
    }
    cx.annotate(summary);
    cx.set_count(Count::Exact(to_u64(members.len()).saturating_add(1)));
    for m in members {
        let mut node = Node::new(m.name.clone())
            .span(through(m.header, m.data))
            .summary(format!("{:#x} bytes", m.data.len));
        node = node.lazy(member, (input, m));
        cx.push(node).await;
    }
    Ok(())
}

/// From the header's start to the end of the data (or of the header).
fn through(header: Span, data: Span) -> Span {
    let end = data.end().max(header.end());
    Span::new(header.source, header.offset, end.saturating_sub(header.offset))
}

async fn member(cx: Cx, (input, m): (Input, Member)) -> Result<()> {
    cx.emit(crate::fields::struct_node("Header", m.header, Endian::Little, (), header));
    match m.kind {
        Kind::Regular if m.data.len > 0 => cx.emit(embedded("Contents", input.nested(m.data))),
        Kind::Regular => cx.emit(Node::new("Contents").desc("Stored outside a thin archive")),
        Kind::LongNames => cx.emit(Node::new("Names").span(m.data).lazy(long_names, m.data)),
        kind => cx.emit(Node::new("Symbols").span(m.data).lazy(symbols, (m.data, kind, input.span))),
    }
    Ok(())
}

async fn long_names(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span.sub(0, 1 << 20)).await?;
    let mut at = 0usize;
    for part in data.split(|&b| b == b'\n' || b == 0) {
        let len = part.len();
        if len > 0 {
            cx.push(
                Node::new(format!("/{at}"))
                    .span(span.sub(to_u64(at), to_u64(len)))
                    .value(text(String::from_utf8_lossy(part).trim_end_matches('/').to_owned())),
            )
            .await;
        }
        at = at.saturating_add(len).saturating_add(1);
    }
    Ok(())
}

/// Symbol index members: `(name, member header offset)` pairs.
async fn symbols(cx: Cx, (span, kind, archive): (Span, Kind, Span)) -> Result<()> {
    if span.len > cx.limits().max_read {
        return Err(Diagnostic::limit("symbol index too large").at(span));
    }
    let data = cx.read(span).await?;
    let mut entries: Vec<(String, u64)> = Vec::new();
    let names_from = |data: &[u8], at: usize, n: usize| -> Vec<String> {
        data.get(at..)
            .unwrap_or_default()
            .split(|&b| b == 0)
            .take(n)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect()
    };
    match kind {
        Kind::SymbolsGnu | Kind::Symbols64 => {
            let wide = kind == Kind::Symbols64;
            let w = if wide { 8 } else { 4 };
            let n = if wide {
                crate::bytes::u64_be(&data, 0).map_or(0, to_usize)
            } else {
                to_usize(u32_be(&data, 0).unwrap_or(0).into())
            };
            let n = n.min(data.len().checked_div(w).unwrap_or(0));
            let offsets: Vec<u64> = (0..n)
                .map(|i| {
                    let at = w.saturating_add(i.saturating_mul(w));
                    if wide {
                        crate::bytes::u64_be(&data, at).unwrap_or(0)
                    } else {
                        u32_be(&data, at).unwrap_or(0).into()
                    }
                })
                .collect();
            let names = names_from(&data, w.saturating_add(n.saturating_mul(w)), n);
            entries.extend(names.into_iter().zip(offsets));
        }
        Kind::SymbolsWindows => {
            let members = to_usize(u32_le(&data, 0).unwrap_or(0).into()).min(data.len() / 4);
            let offsets_at = 4usize;
            let symbols_at = offsets_at.saturating_add(members.saturating_mul(4));
            let n = to_usize(u32_le(&data, symbols_at).unwrap_or(0).into()).min(data.len() / 2);
            let indices_at = symbols_at.saturating_add(4);
            let names = names_from(&data, indices_at.saturating_add(n.saturating_mul(2)), n);
            for (i, name) in names.into_iter().enumerate() {
                let index = usize::from(u16_le(&data, indices_at.saturating_add(i.saturating_mul(2))).unwrap_or(0));
                let offset = index
                    .checked_sub(1)
                    .and_then(|k| u32_le(&data, offsets_at.saturating_add(k.saturating_mul(4))))
                    .unwrap_or(0);
                entries.push((name, offset.into()));
            }
        }
        Kind::SymbolsBsd => {
            let size = to_usize(u32_le(&data, 0).unwrap_or(0).into()).min(data.len());
            let strings_at = 4usize.saturating_add(size).saturating_add(4);
            let strings = data.get(strings_at..).unwrap_or_default();
            for i in 0..size / 8 {
                let at = 4usize.saturating_add(i.saturating_mul(8));
                let strx = to_usize(u32_le(&data, at).unwrap_or(0).into());
                let offset = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
                entries.push((crate::text::until_nul(strings.get(strx..).unwrap_or_default()), offset.into()));
            }
        }
        _ => {}
    }
    cx.set_count(Count::Exact(to_u64(entries.len())));
    for (name, offset) in entries {
        cx.push(
            Node::new(name)
                .value(crate::formats::binutil::hex(offset, 32))
                .summary("member header offset")
                .target(archive.sub(offset, 60)),
        )
        .await;
    }
    Ok(())
}
