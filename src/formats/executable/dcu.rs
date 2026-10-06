//! Delphi compiled units (`.dcu`): the per-unit object files of Borland /
//! CodeGear / Embarcadero Delphi (and C++Builder's Pascal compiler). A DCU
//! holds a unit's interface (for compiling units that use it) and its
//! machine code with fixups (for linking), so it sits with the native
//! objects (OMF, COFF) rather than with interpreted bytecode.
//!
//! The format is undocumented and changes with every compiler version. What
//! is decoded here is reconstructed from memory of Alexei Hmelnov's DCU32INT
//! decompiler and checked against a single Delphi 7 unit; nothing comes from
//! a specification.
//!
//! - **Header** (all versions): a 4-byte magic, the file size (which must
//!   equal the file length) and the compile time as a DOS date/time. The last
//!   byte of the file is the end tag `a`.
//! - **Version**: from Delphi 6 on, the magic's high byte equals the
//!   compiler's `CompilerVersion` (`0x0f` = 15 = Delphi 7); that is verified
//!   for Delphi 7 only, and the mapping of the other values to products is
//!   the public `CompilerVersion` table, not checked against files. The low
//!   three bytes (`0xdf 00 00` for Delphi 7) are shown raw: they are said to
//!   carry platform and edition bits, which are not established here. The
//!   pre-Delphi 6 magics are from memory and unverified.
//! - **Tag stream** (Delphi 7 only, magic `0x0f0000df`): after an 18-byte
//!   header comes a stream of records, each starting with a one-byte tag.
//!   Decoded, in the order they must occur: unit flags (`0x96`, two packed
//!   indices), source files (`p`, and `r` for resource files: a name, a DOS
//!   time stamp and one unknown byte), then the used units, each a `d`
//!   record (name and two raw 32-bit values) followed by the types (`f`) and
//!   values (`g`) imported from it (name and a 32-bit check value) and closed
//!   by `c`. DCU32INT's `e` tag (a unit used from the implementation part)
//!   is accepted with the `d` layout but was not seen in a real file.
//!   Interface and implementation uses are otherwise not distinguished.
//! - Everything after the uses (unit-level declarations, types, procedures,
//!   code, fixups, line numbers) is shown as an unparsed remainder: those
//!   records are version-specific and not understood well enough. The walk
//!   also stops at the first tag that does not fit the grammar above.

use std::sync::Arc;

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::binutil::{dec, hex, text};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "dcu",
    title: "Delphi compiled unit",
    extensions: &["dcu"],
    mime: "application/x-delphi-dcu",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Delphi 7's magic, the only version whose tag stream is decoded.
const MAGIC_D7: u32 = 0x0f00_00df;
/// Header length for Delphi 7 (magic, size, time, a 32-bit value, 2 bytes).
const HEADER_D7: u64 = 18;
/// Header fields common to all versions.
const HEADER_COMMON: u64 = 12;
/// The end tag, the last byte of every unit.
const END_TAG: u8 = b'a';
/// Longest record decoded: tag, counted name, two 32-bit values.
const MAX_RECORD: u64 = 1 + 1 + 255 + 8;

/// Magics of the versions before Delphi 6, which do not follow the
/// `CompilerVersion` pattern. From memory of DCU32INT; unverified.
const OLD_MAGIC: &[(u32, &str)] = &[
    (0x5050_5348, "Delphi 2"),
    (0x4451_8641, "Delphi 3"),
    (0x4768_a6d8, "Delphi 4"),
    (0xf21f_148b, "Delphi 5"),
];

/// `CompilerVersion` (the magic's high byte from Delphi 6 on) to product.
const COMPILER_VERSION: EnumTable = &[
    (14, "Delphi 6 / C++Builder 6 / Kylix"),
    (15, "Delphi 7"),
    (16, "Delphi 8 for .NET"),
    (17, "Delphi 2005"),
    (18, "Delphi / C++Builder 2006 or 2007"),
    (19, "Delphi 2007 for .NET"),
    (20, "Delphi / C++Builder 2009"),
    (21, "Delphi / C++Builder 2010"),
    (22, "Delphi / C++Builder XE"),
    (23, "Delphi / C++Builder XE2"),
    (24, "Delphi / C++Builder XE3"),
    (25, "Delphi / C++Builder XE4"),
    (26, "Delphi / C++Builder XE5"),
    (27, "Delphi / C++Builder XE6"),
    (28, "Delphi / C++Builder XE7"),
    (29, "Delphi / C++Builder XE8"),
    (30, "Delphi / C++Builder 10 Seattle"),
    (31, "Delphi / C++Builder 10.1 Berlin"),
    (32, "Delphi / C++Builder 10.2 Tokyo"),
    (33, "Delphi / C++Builder 10.3 Rio"),
    (34, "Delphi / C++Builder 10.4 Sydney"),
    (35, "Delphi / C++Builder 11 Alexandria"),
    (36, "Delphi / C++Builder 12 Athens"),
    (37, "Delphi / C++Builder 13 Florence"),
];

const TAG: EnumTable = &[
    (0x96, "unit flags"),
    (b'p' as u64, "source file"),
    (b'r' as u64, "resource file"),
    (b'd' as u64, "used unit"),
    (b'e' as u64, "used unit (implementation)"),
    (b'f' as u64, "imported type"),
    (b'g' as u64, "imported value"),
    (b'c' as u64, "end of unit imports"),
];

/// The product a magic stands for, if it is a known DCU magic.
fn version(magic: u32) -> Option<String> {
    if let Some((_, name)) = OLD_MAGIC.iter().find(|(m, _)| *m == magic) {
        return Some((*name).to_owned());
    }
    let cv = magic >> 24;
    lookup(COMPILER_VERSION, cv.into()).map(str::to_owned)
}

/// A DOS date/time (date in the high word) with every field in range.
fn valid_dos_time(v: u32) -> bool {
    let (date, time) = (v >> 16, v & 0xffff);
    let (month, day) = ((date >> 5) & 0xf, date & 0x1f);
    let (hour, minute, sec2) = (time >> 11, (time >> 5) & 0x3f, time & 0x1f);
    (1..=12).contains(&month) && (1..=31).contains(&day) && hour < 24 && minute < 60 && sec2 < 30
}

fn dos_time(v: u32) -> String {
    let date = u16::try_from(v >> 16).unwrap_or(0);
    let time = u16::try_from(v & 0xffff).unwrap_or(0);
    crate::text::dos_datetime(date, time)
}

fn probe(h: &Head<'_>) -> bool {
    let (Some(magic), Some(size), Some(time)) =
        (u32_le(h.data, 0), u32_le(h.data, 4), u32_le(h.data, 8))
    else {
        return false;
    };
    let shape = version(magic).is_some()
        && u64::from(size) == h.len
        && h.len > HEADER_D7
        && valid_dos_time(time)
        && h.tail.last() == Some(&END_TAG);
    // For the version whose stream is understood, the first tag too.
    shape && (magic != MAGIC_D7 || h.data.get(18) == Some(&0x96))
}

/// A DCU packed index (DCU32INT's `ReadUIndex`): the low bits of the first
/// byte say how many bytes follow. Returns the value and its length.
fn packed(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let b0 = *data.get(at)?;
    let le = |n: usize| -> Option<u64> {
        let end = at.checked_add(n)?;
        let bytes = data.get(at..end)?;
        Some(
            bytes
                .iter()
                .rev()
                .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)),
        )
    };
    if b0 & 1 == 0 {
        Some((u64::from(b0 >> 1), 1))
    } else if b0 & 2 == 0 {
        Some((le(2)? >> 2, 2))
    } else if b0 & 4 == 0 {
        Some((le(3)? >> 3, 3))
    } else if b0 & 8 == 0 {
        Some((le(4)? >> 4, 4))
    } else {
        let v = u32_le(data, at.checked_add(1)?)?;
        Some((u64::from(v), 5))
    }
}

/// One decoded field of a record: name, offset and length in the record.
struct Field {
    name: &'static str,
    at: usize,
    len: usize,
    value: Value,
    summary: Option<String>,
    desc: Option<&'static str>,
}

struct Rec {
    tag: u8,
    len: usize,
    name: Option<String>,
    fields: Vec<Field>,
}

enum Stop {
    /// A tag outside the grammar (or one whose layout is not known).
    Unknown(u8),
    /// The record runs past the region.
    Truncated,
}

/// A counted (short) string at `at`: the field and the decoded name.
fn short_string(data: &[u8], at: usize) -> Option<(Field, String)> {
    let n = usize::from(*data.get(at)?);
    let start = at.checked_add(1)?;
    let bytes = data.get(start..start.checked_add(n)?)?;
    let name = crate::text::latin1(bytes);
    let field = Field {
        name: "Name",
        at,
        len: n.checked_add(1)?,
        value: text(name.clone()),
        summary: None,
        desc: Some("Length-prefixed (short) string"),
    };
    Some((field, name))
}

fn raw32(data: &[u8], at: usize, name: &'static str, desc: &'static str) -> Option<Field> {
    let v = u32_le(data, at)?;
    Some(Field {
        name,
        at,
        len: 4,
        value: hex(v.into(), 32),
        summary: None,
        desc: Some(desc),
    })
}

/// Decodes the record at the start of `data` (a window of at most
/// [`MAX_RECORD`] bytes, shorter where the region ends).
fn parse_record(data: &[u8]) -> std::result::Result<Rec, Stop> {
    let Some(&tag) = data.first() else {
        return Err(Stop::Truncated);
    };
    let tag_field = Field {
        name: "Tag",
        at: 0,
        len: 1,
        value: Value::Enum {
            raw: tag.into(),
            bits: 8,
            name: lookup(TAG, tag.into()),
        },
        summary: None,
        desc: None,
    };
    let mut fields = vec![tag_field];
    let mut name = None;
    let mut at = 1usize;
    match tag {
        0x96 => {
            for (label, desc) in [
                ("Flags", "Packed index; called the unit flags in DCU32INT"),
                (
                    "Priority",
                    "Packed index; called the unit priority in DCU32INT",
                ),
            ] {
                let (v, n) = packed(data, at).ok_or(Stop::Truncated)?;
                fields.push(Field {
                    name: label,
                    at,
                    len: n,
                    value: dec(v, 64),
                    summary: None,
                    desc: Some(desc),
                });
                at = at.saturating_add(n);
            }
        }
        b'p' | b'r' | b'd' | b'e' | b'f' | b'g' => {
            let (field, s) = short_string(data, at).ok_or(Stop::Truncated)?;
            at = at.saturating_add(field.len);
            fields.push(field);
            name = Some(s);
            match tag {
                b'p' | b'r' => {
                    let v = u32_le(data, at).ok_or(Stop::Truncated)?;
                    fields.push(Field {
                        name: "Time",
                        at,
                        len: 4,
                        value: text(dos_time(v)),
                        summary: Some(format!("{v:#010x}")),
                        desc: Some("DOS date and time of the file when compiled"),
                    });
                    let b = *data.get(at.saturating_add(4)).ok_or(Stop::Truncated)?;
                    fields.push(Field {
                        name: "Unknown",
                        at: at.saturating_add(4),
                        len: 1,
                        value: hex(b.into(), 8),
                        summary: None,
                        desc: Some("Meaning not established"),
                    });
                    at = at.saturating_add(5);
                }
                b'd' | b'e' => {
                    fields.push(
                        raw32(
                            data,
                            at,
                            "Value 1",
                            "Meaning not established (units compiled together tend to share it)",
                        )
                        .ok_or(Stop::Truncated)?,
                    );
                    fields.push(
                        raw32(
                            data,
                            at.saturating_add(4),
                            "Value 2",
                            "Meaning not established",
                        )
                        .ok_or(Stop::Truncated)?,
                    );
                    at = at.saturating_add(8);
                }
                _ => {
                    fields.push(
                        raw32(
                            data,
                            at,
                            "Check value",
                            "Presumably a signature of the imported declaration; zero for some compiler intrinsics",
                        )
                        .ok_or(Stop::Truncated)?,
                    );
                    at = at.saturating_add(4);
                }
            }
        }
        b'c' => {}
        other => return Err(Stop::Unknown(other)),
    }
    Ok(Rec {
        tag,
        len: at,
        name,
        fields,
    })
}

/// Reads and decodes the record at `pos` in `region`.
async fn read_record(
    cx: &Cx,
    region: Span,
    pos: u64,
) -> Result<(std::result::Result<Rec, Stop>, Span)> {
    let window = region.sub(pos, MAX_RECORD);
    let data = cx.read(window).await?;
    let rec = parse_record(&data);
    let len = rec.as_ref().map_or(0, |r| r.len as u64);
    Ok((rec, region.sub(pos, len)))
}

fn tag_name(tag: u8) -> String {
    lookup(TAG, tag.into()).map_or_else(|| format!("tag {tag:#04x}"), str::to_owned)
}

fn record_node(rec: &Rec, span: Span) -> Node {
    let label = match (rec.tag, &rec.name) {
        (0x96, _) => "Unit flags".to_owned(),
        (_, Some(n)) => n.clone(),
        _ => "End".to_owned(),
    };
    let summary = match rec.tag {
        0x96 => String::new(),
        b'p' | b'r' => rec
            .fields
            .iter()
            .find(|f| f.name == "Time")
            .and_then(|f| match &f.value {
                Value::Text(t) => Some(format!("{}, {t}", tag_name(rec.tag))),
                _ => None,
            })
            .unwrap_or_default(),
        _ => tag_name(rec.tag),
    };
    let node = Node::new(label).span(span).lazy(record_fields, span);
    if summary.is_empty() {
        node
    } else {
        node.summary(summary)
    }
}

async fn record_fields(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let rec = parse_record(&data).map_err(|_| Diagnostic::malformed("record").at(span))?;
    for f in rec.fields {
        let mut node = Node::new(f.name)
            .span(span.sub(f.at as u64, f.len as u64))
            .value(f.value);
        if let Some(s) = f.summary {
            node = node.summary(s);
        }
        if let Some(d) = f.desc {
            node = node.desc(d);
        }
        cx.emit(node);
    }
    Ok(())
}

/// A used unit found by the top-level walk.
#[derive(Clone)]
struct UnitInfo {
    name: String,
    tag: u8,
    /// From the `d` record to the closing `c`, inclusive.
    block: Span,
    imports: u64,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, HEADER_D7)).await?;
    let magic = u32_le(&head, 0).unwrap_or(0);
    let size = u32_le(&head, 4).unwrap_or(0);
    let time = u32_le(&head, 8).unwrap_or(0);
    let product = version(magic).unwrap_or_else(|| "unknown version".to_owned());
    let d7 = magic == MAGIC_D7;
    let header_len = if d7 { HEADER_D7 } else { HEADER_COMMON };
    let hspan = file.sub(0, header_len);
    cx.emit(
        Node::new("Header")
            .span(hspan)
            .summary(product.clone())
            .lazy(header_fields, (hspan, d7)),
    );
    if u64::from(size) != file.len {
        cx.diag(Diagnostic::warning(format!(
            "header says {size} bytes, the file has {}",
            file.len
        )));
    }
    // The end tag, if present, is shown on its own.
    let last = cx.read(file.sub(file.len.saturating_sub(1), 1)).await?;
    let has_end = file.len > header_len && last.first() == Some(&END_TAG);
    let body_end = if has_end {
        file.len.saturating_sub(1)
    } else {
        file.len
    };
    let body = file.sub(0, body_end);

    let mut pos = header_len;
    let mut stop: Option<String> = None;
    let mut sources = 0u64;
    let mut units: Vec<UnitInfo> = Vec::new();
    if d7 {
        // Unit flags.
        let (rec, span) = read_record(&cx, body, pos).await?;
        match rec {
            Ok(r) if r.tag == 0x96 => {
                cx.emit(record_node(&r, span));
                pos = pos.saturating_add(span.len);
            }
            _ => stop = Some("expected the unit flags record (0x96)".to_owned()),
        }
        // Source files.
        let sources_start = pos;
        while stop.is_none() && pos < body.len {
            let (rec, span) = read_record(&cx, body, pos).await?;
            match rec {
                Ok(r) if matches!(r.tag, b'p' | b'r') => {
                    sources = sources.saturating_add(1);
                    pos = pos.saturating_add(span.len);
                }
                _ => break,
            }
        }
        if sources > 0 {
            let region = body.sub(sources_start, pos.saturating_sub(sources_start));
            cx.emit(
                Node::new("Source files")
                    .span(region)
                    .summary(format!("{sources} files"))
                    .lazy(flat_records, (region, sources)),
            );
        }
        // Used units: `d` (or `e`), imports, `c`.
        let uses_start = pos;
        'units: while stop.is_none() && pos < body.len {
            let unit_start = pos;
            let (rec, span) = read_record(&cx, body, pos).await?;
            let r = match rec {
                Ok(r) if matches!(r.tag, b'd' | b'e') => r,
                Ok(r) => {
                    stop = Some(format!("{} not decoded", tag_name(r.tag)));
                    break;
                }
                Err(Stop::Unknown(t)) => {
                    stop = Some(format!("tag {t:#04x} not decoded"));
                    break;
                }
                Err(Stop::Truncated) => {
                    stop = Some("truncated record".to_owned());
                    break;
                }
            };
            pos = pos.saturating_add(span.len);
            let mut imports = 0u64;
            loop {
                if pos >= body.len {
                    stop = Some("used unit not closed".to_owned());
                    pos = unit_start;
                    break 'units;
                }
                let (rec, span) = read_record(&cx, body, pos).await?;
                match rec {
                    Ok(i) if matches!(i.tag, b'f' | b'g') => {
                        imports = imports.saturating_add(1);
                        pos = pos.saturating_add(span.len);
                    }
                    Ok(i) if i.tag == b'c' => {
                        pos = pos.saturating_add(span.len);
                        break;
                    }
                    _ => {
                        stop = Some("unexpected record inside a used unit".to_owned());
                        pos = unit_start;
                        break 'units;
                    }
                }
            }
            units.push(UnitInfo {
                name: r.name.unwrap_or_default(),
                tag: r.tag,
                block: body.sub(unit_start, pos.saturating_sub(unit_start)),
                imports,
            });
        }
        if !units.is_empty() {
            let region = body.sub(uses_start, pos.saturating_sub(uses_start));
            let count = units.len() as u64;
            cx.emit(
                Node::new("Used units")
                    .span(region)
                    .summary(format!("{count} units"))
                    .lazy(used_units, Arc::new(units.clone())),
            );
        }
    } else {
        stop = Some(format!("the record layout of {product} is not decoded"));
    }

    if pos < body.len {
        let rest = body.tail(pos);
        let why = stop.unwrap_or_else(|| "not decoded".to_owned());
        cx.emit(
            Node::new("Unparsed remainder")
                .span(rest)
                .summary(format!("{} bytes; {why}", rest.len))
                .desc(
                    "Declarations, code, fixups and debug records. Their layout varies by \
                     compiler version and is not decoded.",
                ),
        );
    }
    if has_end {
        cx.emit(
            Node::new("End tag")
                .span(file.sub(body_end, 1))
                .value(Value::Enum {
                    raw: END_TAG.into(),
                    bits: 8,
                    name: Some("end of unit"),
                }),
        );
    }

    let mut note = format!("{product} compiled unit");
    if !units.is_empty() {
        note.push_str(&format!(", {} used units", units.len()));
    }
    if sources > 0 {
        note.push_str(&format!(", {sources} source files"));
    }
    if valid_dos_time(time) {
        note.push_str(&format!(", compiled {}", dos_time(time)));
    }
    cx.annotate(note);
    Ok(())
}

async fn header_fields(cx: Cx, (span, d7): (Span, bool)) -> Result<()> {
    let data = cx.read(span).await?;
    let Some(magic) = u32_le(&data, 0) else {
        return Err(Diagnostic::truncated(span.sub(0, 4), span.len));
    };
    let old = OLD_MAGIC.iter().any(|(m, _)| *m == magic);
    let mut node = Node::new("Magic")
        .span(span.sub(0, 4))
        .value(hex(magic.into(), 32));
    if let Some(v) = version(magic) {
        node = node.summary(v);
    }
    if old {
        node = node.desc("Pre-Delphi 6 magic, from memory of DCU32INT (unverified)");
    }
    cx.emit(node);
    if !old {
        let cv = magic >> 24;
        cx.emit(
            Node::new("Compiler version")
                .span(span.sub(3, 1))
                .value(Value::Enum {
                    raw: cv.into(),
                    bits: 8,
                    name: lookup(COMPILER_VERSION, cv.into()),
                })
                .desc(
                    "The magic's high byte, equal to CompilerVersion (verified for Delphi 7 \
                     only; the product names are the public CompilerVersion table)",
                ),
        );
        cx.emit(
            Node::new("Platform / flags")
                .span(span.sub(0, 3))
                .value(hex((magic & 0x00ff_ffff).into(), 24))
                .desc("Low three bytes of the magic; meaning not established"),
        );
    }
    if let Some(size) = u32_le(&data, 4) {
        cx.emit(
            Node::new("File size")
                .span(span.sub(4, 4))
                .value(dec(size.into(), 32)),
        );
    }
    if let Some(t) = u32_le(&data, 8) {
        cx.emit(
            Node::new("Compile time")
                .span(span.sub(8, 4))
                .value(text(dos_time(t)))
                .summary(format!("{t:#010x}"))
                .desc("DOS date and time"),
        );
    }
    if d7 {
        if let Some(v) = u32_le(&data, 12) {
            cx.emit(
                Node::new("Unknown")
                    .span(span.sub(12, 4))
                    .value(hex(v.into(), 32))
                    .desc(
                        "Meaning not established; used-unit records carry values of the same \
                         shape",
                    ),
            );
        }
        for at in [16u64, 17] {
            if let Some(&b) = data.get(at as usize) {
                cx.emit(
                    Node::new("Unknown")
                        .span(span.sub(at, 1))
                        .value(hex(b.into(), 8))
                        .desc("Meaning not established"),
                );
            }
        }
    }
    Ok(())
}

/// Pushes `count` consecutive records of `region`.
async fn flat_records(cx: Cx, (region, count): (Span, u64)) -> Result<()> {
    cx.set_count(Count::Exact(count));
    let mut pos = 0u64;
    while pos < region.len {
        let (rec, span) = read_record(&cx, region, pos).await?;
        let Ok(rec) = rec else {
            return Err(Diagnostic::malformed("record").at(span));
        };
        if span.len == 0 {
            break;
        }
        cx.push(record_node(&rec, span)).await;
        pos = pos.saturating_add(span.len);
    }
    Ok(())
}

async fn used_units(cx: Cx, units: Arc<Vec<UnitInfo>>) -> Result<()> {
    cx.set_count(Count::Exact(units.len() as u64));
    for u in units.iter() {
        let kind = if u.tag == b'e' {
            "implementation, "
        } else {
            ""
        };
        cx.push(
            Node::new(u.name.clone())
                .span(u.block)
                .summary(format!(
                    "{kind}{} import{}",
                    u.imports,
                    if u.imports == 1 { "" } else { "s" }
                ))
                .lazy(flat_records, (u.block, u.imports.saturating_add(2))),
        )
        .await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_index_lengths() {
        assert_eq!(packed(&[0x3c], 0), Some((30, 1)));
        assert_eq!(packed(&[0x59, 0x02], 0), Some((0x96, 2)));
        assert_eq!(packed(&[0x03, 0x00, 0x01], 0), Some((0x2000, 3)));
        assert_eq!(packed(&[0x0f, 1, 2, 3, 4], 0), Some((0x0403_0201, 5)));
        assert_eq!(packed(&[0x01], 0), None);
    }

    #[test]
    fn dos_time_validation() {
        assert!(valid_dos_time(0x3475_8f0d));
        assert!(!valid_dos_time(0));
        assert!(!valid_dos_time(0x3475_8f1e)); // 60 seconds
    }

    #[test]
    fn versions() {
        assert_eq!(version(MAGIC_D7).as_deref(), Some("Delphi 7"));
        assert_eq!(version(0x0d00_00df), None);
        assert_eq!(version(0x7f00_00df), None);
    }
}
