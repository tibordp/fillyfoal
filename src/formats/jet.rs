//! Microsoft Access databases: Jet (`.mdb`) and ACE (`.accdb`). Page 0
//! holds the file header, part of which is obfuscated with RC4 (key
//! `0x6b39dac7`); it is decrypted into a derived source. Pages are listed by
//! number with their type; data pages show their row offsets.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Radix, Value, lookup};

pub static MDB: Format = Format {
    name: "mdb",
    title: "Microsoft Access database (Jet)",
    extensions: &["mdb", "mde", "mdw"],
    mime: "application/x-msaccess",
    probe: Probe::Custom(|h| h.starts_with(&[0, 1, 0, 0]) && h.at(4, b"Standard Jet DB\0")),
    dissect: crate::expander!(dissect: Input),
};

pub static ACCDB: Format = Format {
    name: "accdb",
    title: "Microsoft Access database (ACE)",
    extensions: &["accdb", "accde", "laccdb"],
    mime: "application/x-msaccess",
    probe: Probe::Custom(|h: &Head<'_>| {
        h.starts_with(&[0, 1, 0, 0]) && h.at(4, b"Standard ACE DB\0")
    }),
    dissect: crate::expander!(dissect: Input),
};

const VERSIONS: EnumTable = &[
    (0, "Jet 3 (Access 97)"),
    (1, "Jet 4 (Access 2000-2003)"),
    (2, "ACE 12 (Access 2007)"),
    (3, "ACE 14 (Access 2010)"),
    (4, "ACE 15 (Access 2013)"),
    (5, "ACE 16 (Access 2016)"),
    (6, "ACE 17 (Access 2019)"),
];

const PAGE_TYPES: EnumTable = &[
    (0x00, "database definition"),
    (0x01, "data"),
    (0x02, "table definition"),
    (0x03, "intermediate index"),
    (0x04, "leaf index"),
    (0x05, "page usage bitmap"),
];

const KEY: [u8; 4] = [0xc7, 0xda, 0x39, 0x6b];

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256usize {
        let si = s.get(i).copied().unwrap_or(0);
        j = j.wrapping_add(si).wrapping_add(
            key.get(i.checked_rem(key.len()).unwrap_or(0))
                .copied()
                .unwrap_or(0),
        );
        s.swap(i, usize::from(j));
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s.get(usize::from(i)).copied().unwrap_or(0));
            s.swap(usize::from(i), usize::from(j));
            let k = s
                .get(usize::from(
                    s.get(usize::from(i))
                        .copied()
                        .unwrap_or(0)
                        .wrapping_add(s.get(usize::from(j)).copied().unwrap_or(0)),
                ))
                .copied()
                .unwrap_or(0);
            b ^ k
        })
        .collect()
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x18)).await?;
    let version = u32_le(&head, 0x14).unwrap_or(0);
    let jet3 = version == 0;
    let page_size: u64 = if jet3 { 2048 } else { 4096 };
    cx.emit(
        Node::new("Page type")
            .span(file.sub(0, 4))
            .value(Value::Bytes(head.get(..4).unwrap_or_default().to_vec())),
    );
    cx.emit(
        Node::new("Format ID")
            .span(file.sub(4, 16))
            .value(Value::Text(crate::text::until_nul(
                head.get(4..20).unwrap_or_default(),
            ))),
    );
    cx.emit(
        Node::new("Version")
            .span(file.sub(0x14, 4))
            .value(Value::Enum {
                raw: version.into(),
                bits: 32,
                name: lookup(VERSIONS, version.into()),
            }),
    );
    let enc_len: u64 = if jet3 { 126 } else { 128 };
    let enc = file.sub(0x18, enc_len);
    let raw = cx.read(enc).await?;
    let decoded = cx.add_derived(
        Origin {
            parent: enc,
            transform: "jet-rc4",
        },
        rc4(&KEY, &raw),
        enc_len,
        None,
    )?;
    let plain = cx.read(decoded.span).await?;
    let mut header = Node::new("Database header")
        .span(enc)
        .summary("RC4-obfuscated")
        .lazy(header_fields, (decoded.span, jet3));
    if raw.len() < crate::bytes::to_usize(enc_len) {
        header = header.diag(Diagnostic::truncated(enc, to_u64(raw.len())));
    }
    cx.emit(header);
    let pages = file.len.checked_div(page_size).unwrap_or(0);
    let codepage = if jet3 {
        u16_le(&plain, 0x3a - 0x18)
    } else {
        u16_le(&plain, 0x3c - 0x18)
    };
    let mut summary = format!(
        "Access database, {}, {pages} pages of {page_size} bytes",
        lookup(VERSIONS, version.into()).unwrap_or("unknown version")
    );
    if let Some(cp) = codepage.filter(|&c| c != 0) {
        summary = format!("{summary}, code page {cp}");
    }
    cx.annotate(summary);
    cx.emit(
        Node::new("Pages")
            .summary(format!("{pages}"))
            .lazy(page_list, (input, page_size, jet3)),
    );
    Ok(())
}

async fn header_fields(cx: Cx, (span, jet3): (Span, bool)) -> Result<()> {
    let data = cx.read(span).await?;
    // Offsets below are relative to the start of page 0.
    let at = |o: u64| span.sub(o.saturating_sub(0x18), 2);
    let u16_at = |o: u64| u16_le(&data, to_usize(o.saturating_sub(0x18))).unwrap_or(0);
    let (cp, collation) = if jet3 { (0x3a, 0x56) } else { (0x3c, 0x56) };
    cx.emit(Node::new("Code page").span(at(cp)).value(Value::UInt {
        value: u16_at(cp).into(),
        bits: 16,
        radix: Radix::Dec,
    }));
    cx.emit(
        Node::new("Collation")
            .span(at(collation))
            .value(Value::UInt {
                value: u16_at(collation).into(),
                bits: 16,
                radix: Radix::Hex,
            }),
    );
    cx.emit(
        Node::new("Decrypted bytes")
            .span(span)
            .value(Value::Bytes(data.iter().take(32).copied().collect())),
    );
    Ok(())
}

async fn page_list(cx: Cx, (input, page_size, jet3): (Input, u64, bool)) -> Result<()> {
    let file = input.span;
    let pages = file.len.checked_div(page_size).unwrap_or(0);
    cx.set_count(Count::Exact(pages));
    for no in 0..pages {
        let span = file.sub(no.saturating_mul(page_size), page_size);
        let head = cx.read_avail(span.sub(0, 16)).await?;
        let kind = head.first().copied().unwrap_or(0);
        let mut summary = lookup(PAGE_TYPES, kind.into())
            .unwrap_or("unknown")
            .to_owned();
        if kind == 1 {
            let rows = u16_le(&head, if jet3 { 8 } else { 12 }).unwrap_or(0);
            summary = format!(
                "{summary}, {rows} rows, table definition at page {}",
                u32_le(&head, 4).unwrap_or(0)
            );
        }
        let mut node = Node::new(format!("Page {no}")).span(span).summary(summary);
        if kind == 1 && no > 0 {
            node = node.lazy(data_page, (span, jet3));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn data_page(cx: Cx, (span, jet3): (Span, bool)) -> Result<()> {
    let data = cx.read(span).await?;
    let rows_at: usize = if jet3 { 8 } else { 12 };
    let u16v = |v: u16| Value::UInt {
        value: v.into(),
        bits: 16,
        radix: Radix::Dec,
    };
    cx.emit(
        Node::new("Free space")
            .span(span.sub(2, 2))
            .value(u16v(u16_le(&data, 2).unwrap_or(0))),
    );
    cx.emit(
        Node::new("Table definition page")
            .span(span.sub(4, 4))
            .value(Value::UInt {
                value: u32_le(&data, 4).unwrap_or(0).into(),
                bits: 32,
                radix: Radix::Dec,
            }),
    );
    let rows = u16_le(&data, rows_at).unwrap_or(0);
    cx.emit(
        Node::new("Row count")
            .span(span.sub(to_u64(rows_at), 2))
            .value(u16v(rows)),
    );
    // Row offsets: rows are stored from the end of the page downwards.
    let mut end = data.len();
    for i in 0..usize::from(rows) {
        let at = rows_at
            .saturating_add(2)
            .saturating_add(i.saturating_mul(2));
        let Some(raw) = u16_le(&data, at) else { break };
        let flags = raw & 0xe000;
        let off = usize::from(raw & 0x1fff);
        let row = span.sub(to_u64(off), to_u64(end.saturating_sub(off)));
        let mut node = Node::new(format!("Row {i}")).span(row).value(Value::UInt {
            value: raw.into(),
            bits: 16,
            radix: Radix::Hex,
        });
        if flags & 0x4000 != 0 {
            node = node.summary("overflow pointer");
        } else if flags & 0x8000 != 0 {
            node = node.summary("deleted");
        } else {
            node = node.summary(format!("{} bytes", row.len));
        }
        if off < end {
            end = off;
        }
        cx.push(node).await;
    }
    Ok(())
}
