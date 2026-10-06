//! ACE and SEA ARC archives.
//!
//! ACE: blocks with a CRC-16, size, type and flags; the main header carries
//! the `**ACE**` signature, file headers carry sizes, attributes, CRC-32 and
//! the compression type, followed by the packed data.
//!
//! ARC: a chain of `0x1A`-prefixed headers (method, 13-byte name, sizes,
//! DOS time, CRC-16), ending with method 0.
//!
//! Stored members are dissected in place; the LZ77/Huffman (ACE) and
//! RLE/Huffman/LZW (ARC) methods are unsupported leaves.

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::codec::crc32;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::arcutil::{ByteReader, count, emit_nodes, hex, human_size, unsupported};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const MAX_ENTRIES: u64 = 1 << 20;

pub static ACE: Format = Format {
    name: "ace",
    title: "ACE archive",
    extensions: &["ace", "cba"],
    mime: "application/x-ace-compressed",
    probe: Probe::Magic(&[(7, b"**ACE**")]),
    dissect: crate::expander!(dissect_ace: Input),
};

pub static ARC: Format = Format {
    name: "arc",
    title: "ARC archive (SEA)",
    extensions: &["arc", "ark", "pak"],
    mime: "application/x-arc",
    probe: Probe::Custom(probe_arc),
    dissect: crate::expander!(dissect_arc: Input),
};

// ---------------------------------------------------------------------------
// ACE

const ACE_TYPE: EnumTable = &[
    (0, "main header"),
    (1, "file (32-bit sizes)"),
    (2, "recovery record (32-bit)"),
    (3, "file (64-bit sizes)"),
    (4, "recovery record (64-bit, A)"),
    (5, "recovery record (64-bit, B)"),
];

const ACE_FILE_FLAGS: FlagTable = &[
    flag(0x0001, "ADDSIZE"),
    flag(0x0002, "COMMENT"),
    flag(0x0004, "64BIT"),
    flag(0x1000, "SPLIT_BEFORE"),
    flag(0x2000, "SPLIT_AFTER"),
    flag(0x4000, "PASSWORD"),
    flag(0x8000, "SOLID"),
];

const ACE_MAIN_FLAGS: FlagTable = &[
    flag(0x0002, "COMMENT"),
    flag(0x0100, "SFX"),
    flag(0x0200, "LIMIT_SFX"),
    flag(0x0400, "MULTIVOLUME"),
    flag(0x0800, "AV"),
    flag(0x1000, "RECOVERY"),
    flag(0x2000, "LOCKED"),
    flag(0x4000, "SOLID"),
];

const ACE_HOST: EnumTable = &[
    (0, "MS-DOS"),
    (1, "OS/2"),
    (2, "Win32"),
    (3, "Unix"),
    (4, "Mac OS"),
    (5, "Win NT"),
    (6, "Primos"),
    (7, "Apple GS"),
    (8, "Atari"),
    (9, "VAX VMS"),
    (10, "Amiga"),
    (11, "NeXT"),
];

const ACE_COMP: EnumTable = &[(0, "stored"), (1, "LZ77"), (2, "blocked")];

/// ACE's header CRC: CRC-32 without the final inversion, low 16 bits.
fn ace_crc(data: &[u8]) -> u16 {
    u16::try_from(!crc32(data) & 0xffff).unwrap_or(0)
}

pub async fn dissect_ace(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let mut files = 0u64;
    let mut total = 0u64;
    let mut seen = 0u64;
    cx.annotate("ACE archive");
    while at.saturating_add(7) <= file.len && seen < MAX_ENTRIES {
        seen = seen.saturating_add(1);
        let head = cx.read(file.sub(at, 4)).await?;
        let size = u64::from(u16_le(&head, 2).unwrap_or(0));
        let header_span = file.sub(at, size.saturating_add(4));
        let header = cx.read(header_span).await?;
        let kind = header.get(4).copied().unwrap_or(0);
        let flags = u16_le(&header, 5).unwrap_or(0);
        let crc_ok = header
            .get(4..)
            .is_some_and(|b| Some(ace_crc(b)) == u16_le(&header, 0));
        let wide = kind == 3 || kind == 5;
        let (packed, original) = if flags & 0x0001 != 0 {
            if wide {
                (
                    u64_le(&header, 7).unwrap_or(0),
                    u64_le(&header, 15).unwrap_or(0),
                )
            } else {
                (
                    u64::from(u32_le(&header, 7).unwrap_or(0)),
                    u64::from(u32_le(&header, 11).unwrap_or(0)),
                )
            }
        } else {
            (0, 0)
        };
        let span = file.sub(at, header_span.len.saturating_add(packed));
        let (name, summary) = match kind {
            0 => ("Main header".to_owned(), String::new()),
            1 | 3 => {
                let name_at = if wide { 43usize } else { 35 };
                let len = usize::from(u16_le(&header, name_at.saturating_sub(2)).unwrap_or(0));
                let name = header
                    .get(name_at..name_at.saturating_add(len))
                    .unwrap_or_default();
                files = files.saturating_add(1);
                total = total.saturating_add(original);
                (
                    String::from_utf8_lossy(name).replace('\\', "/"),
                    human_size(original),
                )
            }
            _ => (
                crate::value::lookup(ACE_TYPE, kind.into())
                    .unwrap_or("unknown block")
                    .to_owned(),
                human_size(packed),
            ),
        };
        let mut node = Node::new(name)
            .span(span)
            .lazy(ace_block, (input, span, header_span));
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if !crc_ok {
            node = node.diag(Diagnostic::warning("header CRC mismatch"));
        }
        cx.push(node).await;
        if size == 0 {
            break;
        }
        at = at.saturating_add(span.len);
    }
    cx.annotate(format!(
        "ACE archive, {}, {} uncompressed",
        count(files, "file", "files"),
        human_size(total)
    ));
    Ok(())
}

async fn ace_block(cx: Cx, (input, span, header_span): (Input, Span, Span)) -> Result<()> {
    let header = cx.read(header_span).await?;
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::truncated(header_span, 0);
    let stored = r.u16("Header CRC", LE).ok_or_else(bad)?;
    let computed = ace_crc(header.get(4..).unwrap_or_default());
    r.with(|n| {
        let n = n.value(hex(stored.into()));
        if stored == computed {
            n.summary("valid")
        } else {
            n.diag(Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#06x}"
            )))
        }
    });
    r.u16("Header size", LE).ok_or_else(bad)?;
    let kind = r.u8("Header type").ok_or_else(bad)?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: kind.into(),
            bits: 8,
            name: crate::value::lookup(ACE_TYPE, kind.into()),
        })
    });
    let flags = r.u16("Flags", LE).ok_or_else(bad)?;
    let table = if kind == 0 {
        ACE_MAIN_FLAGS
    } else {
        ACE_FILE_FLAGS
    };
    r.with(|n| {
        let (set, unknown) = crate::value::decode_flags(table, flags.into());
        n.value(Value::Flags {
            raw: flags.into(),
            bits: 16,
            set,
            unknown,
        })
    });
    let mut data = None;
    match kind {
        0 => {
            r.text("Signature", 7).ok_or_else(bad)?;
            r.u8("Version needed").ok_or_else(bad)?;
            r.u8("Version created").ok_or_else(bad)?;
            let host = r.u8("Host OS").ok_or_else(bad)?;
            r.with(|n| {
                n.value(Value::Enum {
                    raw: host.into(),
                    bits: 8,
                    name: crate::value::lookup(ACE_HOST, host.into()),
                })
            });
            r.u8("Volume number").ok_or_else(bad)?;
            dos_time(&mut r, "Creation time").ok_or_else(bad)?;
            r.bytes("Reserved", 8).ok_or_else(bad)?;
            let av = r.u8("AV size").ok_or_else(bad)?;
            if av > 0 {
                r.text("AV string", av.into()).ok_or_else(bad)?;
            }
        }
        1 | 3 => {
            let wide = kind == 3;
            let packed = if wide {
                let p = r.u64("Packed size", LE).ok_or_else(bad)?;
                r.u64("Original size", LE).ok_or_else(bad)?;
                p
            } else {
                let p = r.u32("Packed size", LE).ok_or_else(bad)?;
                r.u32("Original size", LE).ok_or_else(bad)?;
                p.into()
            };
            dos_time(&mut r, "Modification time").ok_or_else(bad)?;
            let attr = r.u32("Attributes", LE).ok_or_else(bad)?;
            r.with(|n| n.value(hex(attr.into())));
            let crc = r.u32("CRC-32", LE).ok_or_else(bad)?;
            r.with(|n| n.value(hex(crc.into())));
            let comp = r.u8("Compression type").ok_or_else(bad)?;
            r.with(|n| {
                n.value(Value::Enum {
                    raw: comp.into(),
                    bits: 8,
                    name: crate::value::lookup(ACE_COMP, comp.into()),
                })
            });
            r.u8("Compression quality").ok_or_else(bad)?;
            r.u16("Compression parameters", LE).ok_or_else(bad)?;
            r.u16("Reserved", LE).ok_or_else(bad)?;
            let len = r.u16("Name size", LE).ok_or_else(bad)?;
            r.text("Name", len.into()).ok_or_else(bad)?;
            let d = span.tail(header_span.len);
            let d = d.sub(0, packed);
            data = Some(if flags & 0x4000 != 0 {
                Node::new("Encrypted data")
                    .span(d)
                    .diag(Diagnostic::unsupported("encrypted file"))
            } else if flags & 0x3000 != 0 {
                Node::new("Data (split across volumes)")
                    .span(d)
                    .diag(Diagnostic::unsupported("multi-volume member"))
            } else if comp == 0 {
                embedded("Content", input.nested(d)).summary(human_size(packed))
            } else {
                let c = crate::value::lookup(ACE_COMP, comp.into()).unwrap_or("unknown");
                unsupported("Compressed data", d, &format!("ACE {c}"))
            });
        }
        _ => {
            if flags & 0x0001 != 0 {
                let d = span.tail(header_span.len);
                data = Some(Node::new("Data").span(d));
            }
        }
    }
    if r.remaining() > 0 {
        r.bytes("Rest of header", to_u64(r.remaining()));
    }
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .lazy(emit_nodes, r.into_nodes()),
    );
    if let Some(d) = data {
        cx.emit(d);
    }
    Ok(())
}

fn dos_time(r: &mut ByteReader<'_>, name: &'static str) -> Option<()> {
    let t = r.u32(name, LE)?;
    r.with(|n| {
        n.value(hex(t.into())).summary(crate::text::dos_datetime(
            u16::try_from(t >> 16).unwrap_or(0),
            u16::try_from(t & 0xffff).unwrap_or(0),
        ))
    });
    Some(())
}

// ---------------------------------------------------------------------------
// ARC

const ARC_METHOD: EnumTable = &[
    (0, "end of archive"),
    (1, "stored (old)"),
    (2, "stored"),
    (3, "packed (RLE)"),
    (4, "squeezed (RLE + Huffman)"),
    (5, "crunched (LZW, old)"),
    (6, "crunched (RLE + LZW, old)"),
    (7, "crunched (RLE + LZW, fast)"),
    (8, "crunched (RLE + dynamic LZW)"),
    (9, "squashed (13-bit LZW)"),
    (10, "crushed (PAK)"),
    (11, "distilled (PAK)"),
];

fn probe_arc(h: &Head<'_>) -> bool {
    let d = h.data;
    let method_ok = d.get(1).is_some_and(|&m| (1..=11).contains(&m));
    let name = d.get(2..15).unwrap_or_default();
    let nul = name.iter().position(|&b| b == 0);
    let name_ok = nul.is_some_and(|n| {
        n > 0
            && name
                .get(..n)
                .is_some_and(|s| s.iter().all(|&c| c.is_ascii_graphic()))
    });
    let size_ok = u32_le(d, 15).is_some_and(|s| u64::from(s) <= h.len);
    d.first() == Some(&0x1a) && method_ok && name_ok && size_ok
}

pub async fn dissect_arc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let mut files = 0u64;
    let mut total = 0u64;
    let mut seen = 0u64;
    while at < file.len && seen < MAX_ENTRIES {
        seen = seen.saturating_add(1);
        let head = cx.read_avail(file.sub(at, 29)).await?;
        if head.first() != Some(&0x1a) {
            cx.emit(
                Node::new("Trailing data")
                    .span(file.tail(at))
                    .diag(Diagnostic::malformed("expected a 0x1A header marker")),
            );
            break;
        }
        let method = head.get(1).copied().unwrap_or(0);
        if method == 0 {
            cx.emit(Node::new("End of archive").span(file.sub(at, 2)));
            at = at.saturating_add(2);
            break;
        }
        let header_len = if method == 1 { 25u64 } else { 29 };
        let packed = u64::from(u32_le(&head, 15).unwrap_or(0));
        let original = if method == 1 {
            packed
        } else {
            u64::from(u32_le(&head, 25).unwrap_or(0))
        };
        let name = crate::text::until_nul(head.get(2..15).unwrap_or_default());
        let span = file.sub(at, header_len.saturating_add(packed));
        files = files.saturating_add(1);
        total = total.saturating_add(original);
        let m = crate::value::lookup(ARC_METHOD, method.into()).unwrap_or("unknown method");
        cx.push(
            Node::new(name)
                .span(span)
                .summary(format!("{}, {m}", human_size(original)))
                .lazy(arc_entry, (input, span, header_len)),
        )
        .await;
        at = at.saturating_add(span.len.max(2));
    }
    if at < file.len {
        cx.emit(Node::new("Data after the archive").span(file.tail(at)));
    }
    cx.annotate(format!(
        "ARC archive, {}, {} uncompressed",
        count(files, "file", "files"),
        human_size(total)
    ));
    Ok(())
}

async fn arc_entry(cx: Cx, (input, span, header_len): (Input, Span, u64)) -> Result<()> {
    let header_span = span.sub(0, header_len);
    let header = cx.read(header_span).await?;
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::truncated(header_span, 0);
    r.u8("Marker").ok_or_else(bad)?;
    let method = r.u8("Method").ok_or_else(bad)?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: method.into(),
            bits: 8,
            name: crate::value::lookup(ARC_METHOD, method.into()),
        })
    });
    let raw = r.bytes("Name", 13).ok_or_else(bad)?;
    let name = crate::text::until_nul(raw);
    r.with(|n| n.value(Value::Text(name)));
    let packed = r.u32("Compressed size", LE).ok_or_else(bad)?;
    let date = r.u16("Date", LE).ok_or_else(bad)?;
    let time = r.u16("Time", LE).ok_or_else(bad)?;
    r.with(|n| n.summary(crate::text::dos_datetime(date, time)));
    let crc = r.u16("CRC-16", LE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(crc.into())));
    if method != 1 {
        r.u32("Original size", LE).ok_or_else(bad)?;
    }
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .lazy(emit_nodes, r.into_nodes()),
    );
    let data = span.sub(header_len, packed.into());
    let node = if method <= 2 {
        embedded("Content", input.nested(data)).summary(human_size(packed.into()))
    } else {
        let m = crate::value::lookup(ARC_METHOD, method.into()).unwrap_or("unknown");
        unsupported("Compressed data", data, &format!("ARC {m}"))
    };
    cx.emit(crate::formats::arcutil::check_len(
        node,
        data,
        packed.into(),
    ));
    Ok(())
}
