//! Unity IL2CPP metadata (`global-metadata.dat`): the header's table of
//! `(offset, size)` pairs, the identifier string table and the string
//! literals. Table layouts beyond the first three vary by version, so the
//! rest are listed by index.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::util::binutil::{dec, hex, text};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;

pub static FORMAT: Format = Format {
    name: "il2cpp-metadata",
    title: "Unity IL2CPP metadata",
    extensions: &["dat"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| {
        h.starts_with(b"\xaf\x1b\xb1\xfa")
            && u32_le(h.data, 4).is_some_and(|v| (16..=40).contains(&v))
    }),
    dissect: crate::expander!(dissect: Input),
};

const NAMES: &[&str] = &["stringLiteral", "stringLiteralData", "string"];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x400)).await?;
    let version = u32_le(&head, 4).unwrap_or(0);
    cx.emit(
        Node::new("sanity")
            .span(file.sub(0, 4))
            .value(hex(0xfab1_1baf, 32)),
    );
    cx.emit(
        Node::new("version")
            .span(file.sub(4, 4))
            .value(dec(version.into(), 32)),
    );
    // The header ends where the first table starts.
    let first = u32_le(&head, 8).unwrap_or(0).clamp(8, 0x400);
    let pairs = to_usize(u64::from(first.saturating_sub(8)) / 8);
    let mut tables = Vec::new();
    for i in 0..pairs {
        let at = 8usize.saturating_add(i.saturating_mul(8));
        let (Some(offset), Some(size)) = (u32_le(&head, at), u32_le(&head, at.saturating_add(4)))
        else {
            break;
        };
        tables.push((
            file.sub(to_u64(at), 8),
            file.sub(offset.into(), size.into()),
            size,
        ));
    }
    let literal_count = tables.first().map_or(0, |(_, _, s)| s / 8);
    let identifiers = tables.get(2).map_or(0, |(_, span, _)| span.len);
    cx.annotate(format!(
        "Unity IL2CPP metadata v{version}, {} tables, {literal_count} string literals, {identifiers:#x} bytes of identifiers",
        tables.len()
    ));
    for (i, (entry, span, size)) in tables.iter().copied().enumerate() {
        let name = NAMES
            .get(i)
            .map_or_else(|| format!("table {i}"), |n| (*n).to_owned());
        let node = Node::new(name)
            .span(entry)
            .summary(format!(
                "{size:#x} bytes at {:#x}",
                span.offset.saturating_sub(file.offset)
            ))
            .target(span);
        let node = match i {
            0 => match tables.get(1) {
                Some((_, data, _)) => node.lazy(literals, (span, *data, version)),
                None => node,
            },
            2 => node.lazy(crate::formats::util::binutil::cstrings, span),
            _ => node,
        };
        cx.emit(node);
    }
    Ok(())
}

/// String literal entries: `(length, data index)` into the literal data
/// (version 31 and later store only the index; lengths come from the next
/// entry).
async fn literals(cx: Cx, (table, data, version): (Span, Span, u32)) -> Result<()> {
    let entries = cx.read(table.sub(0, 0x10_0000)).await?;
    let width = if version >= 31 { 4usize } else { 8 };
    let count = entries.len().checked_div(width).unwrap_or(0);
    cx.set_count(Count::Exact(to_u64(count)));
    for i in 0..count {
        let at = i.saturating_mul(width);
        let (len, index) = if width == 8 {
            (
                u32_le(&entries, at).unwrap_or(0),
                u32_le(&entries, at.saturating_add(4)).unwrap_or(0),
            )
        } else {
            let index = u32_le(&entries, at).unwrap_or(0);
            let next = u32_le(&entries, at.saturating_add(4))
                .unwrap_or(u32::try_from(data.len).unwrap_or(0));
            (next.saturating_sub(index), index)
        };
        let span = data.sub(index.into(), len.into());
        let bytes = cx.read_avail(span.sub(0, 4096)).await?;
        cx.push(
            Node::new(format!("{i}"))
                .span(table.sub(to_u64(at), to_u64(width)))
                .value(text(String::from_utf8_lossy(&bytes).into_owned()))
                .target(span),
        )
        .await;
    }
    Ok(())
}
