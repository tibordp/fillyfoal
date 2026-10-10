//! BUFR (WMO FM 94) observation messages, editions 2–4.
//!
//! A message is `BUFR`, a 24-bit total length and the edition (section 0),
//! then sections 1 (identification), 2 (optional local data), 3 (the data
//! description: number of subsets, flags and a list of F-X-Y descriptors),
//! 4 (the bit-packed data) and `7777`. Sections 1–4 start with a 24-bit
//! length; section 1's layout depends on the edition.
//!
//! The data in section 4 can only be read with the descriptor tables: each
//! element descriptor (F = 0) has a width, scale and reference value in
//! Table B, sequences (F = 3) expand through Table D, F = 1 replicates and
//! F = 2 changes widths and scales. We carry a small built-in subset of
//! Tables B and D (station identification, date and time, position,
//! temperature, pressure, wind, humidity, cloud cover) and the 2-01/2-02
//! operators; when every descriptor of a message is covered, the subsets are
//! decoded (plain or compressed), otherwise the data stays a raw leaf naming
//! the first unknown descriptor. Layouts and table entries are from memory
//! of the WMO Manual on Codes; the ecCodes-written fixtures decode to the
//! values that were encoded.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::Input;
use crate::formats::science::numarray::num;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

const BE: Endian = Endian::Big;

use super::grib::{CENTRES, indicator1, rest, u24};

const CATEGORIES: EnumTable = &[
    (0, "surface data, land"),
    (1, "surface data, sea"),
    (2, "vertical soundings (other than satellite)"),
    (3, "vertical soundings (satellite)"),
    (4, "single level upper-air data (other than satellite)"),
    (5, "single level upper-air data (satellite)"),
    (6, "radar data"),
    (7, "synoptic features"),
    (8, "physical/chemical constituents"),
    (9, "dispersal and transport"),
    (10, "radiological data"),
    (11, "BUFR tables"),
    (12, "surface data (satellite)"),
    (21, "radiances (satellite measured)"),
    (31, "oceanographic data"),
    (101, "image data"),
];

/// A Table B element: name, unit, scale, reference value, width in bits.
struct ElementDef {
    name: &'static str,
    unit: &'static str,
    scale: i32,
    reference: i64,
    width: u16,
}

const fn fxy(f: u16, x: u16, y: u16) -> u16 {
    (f << 14) | (x << 8) | y
}

fn table_b(d: u16) -> Option<ElementDef> {
    let e = |name, unit, scale, reference, width| ElementDef {
        name,
        unit,
        scale,
        reference,
        width,
    };
    Some(match d {
        x if x == fxy(0, 1, 1) => e("WMO block number", "", 0, 0, 7),
        x if x == fxy(0, 1, 2) => e("WMO station number", "", 0, 0, 10),
        x if x == fxy(0, 2, 1) => e("Type of station", "code table", 0, 0, 2),
        x if x == fxy(0, 4, 1) => e("Year", "a", 0, 0, 12),
        x if x == fxy(0, 4, 2) => e("Month", "mon", 0, 0, 4),
        x if x == fxy(0, 4, 3) => e("Day", "d", 0, 0, 6),
        x if x == fxy(0, 4, 4) => e("Hour", "h", 0, 0, 5),
        x if x == fxy(0, 4, 5) => e("Minute", "min", 0, 0, 6),
        x if x == fxy(0, 4, 6) => e("Second", "s", 0, 0, 6),
        x if x == fxy(0, 5, 1) => e("Latitude (high accuracy)", "deg", 5, -9_000_000, 25),
        x if x == fxy(0, 5, 2) => e("Latitude (coarse accuracy)", "deg", 2, -9_000, 15),
        x if x == fxy(0, 6, 1) => e("Longitude (high accuracy)", "deg", 5, -18_000_000, 26),
        x if x == fxy(0, 6, 2) => e("Longitude (coarse accuracy)", "deg", 2, -18_000, 16),
        x if x == fxy(0, 7, 1) => e("Height of station", "m", 0, -400, 15),
        x if x == fxy(0, 7, 30) => e(
            "Height of station ground above mean sea level",
            "m",
            1,
            -4_000,
            17,
        ),
        x if x == fxy(0, 10, 4) => e("Pressure", "Pa", -1, 0, 14),
        x if x == fxy(0, 10, 51) => e("Pressure reduced to mean sea level", "Pa", -1, 0, 14),
        x if x == fxy(0, 11, 1) => e("Wind direction", "deg", 0, 0, 9),
        x if x == fxy(0, 11, 2) => e("Wind speed", "m/s", 1, 0, 12),
        x if x == fxy(0, 12, 101) => e("Air temperature", "K", 2, 0, 16),
        x if x == fxy(0, 12, 103) => e("Dew-point temperature", "K", 2, 0, 16),
        x if x == fxy(0, 13, 3) => e("Relative humidity", "%", 0, 0, 7),
        x if x == fxy(0, 20, 10) => e("Cloud cover (total)", "%", 0, 0, 7),
        x if x == fxy(0, 31, 0) => e("Short delayed descriptor replication factor", "", 0, 0, 1),
        x if x == fxy(0, 31, 1) => e("Delayed descriptor replication factor", "", 0, 0, 8),
        x if x == fxy(0, 31, 2) => e(
            "Extended delayed descriptor replication factor",
            "",
            0,
            0,
            16,
        ),
        _ => return None,
    })
}

fn table_d(d: u16) -> Option<(&'static str, &'static [u16])> {
    const BLOCK_STATION: &[u16] = &[fxy(0, 1, 1), fxy(0, 1, 2)];
    const DATE: &[u16] = &[fxy(0, 4, 1), fxy(0, 4, 2), fxy(0, 4, 3)];
    const TIME_HM: &[u16] = &[fxy(0, 4, 4), fxy(0, 4, 5)];
    const TIME_HMS: &[u16] = &[fxy(0, 4, 4), fxy(0, 4, 5), fxy(0, 4, 6)];
    const POSITION: &[u16] = &[fxy(0, 5, 1), fxy(0, 6, 1)];
    Some(match d {
        x if x == fxy(3, 1, 1) => ("WMO block and station numbers", BLOCK_STATION),
        x if x == fxy(3, 1, 11) => ("Year, month, day", DATE),
        x if x == fxy(3, 1, 12) => ("Hour, minute", TIME_HM),
        x if x == fxy(3, 1, 13) => ("Hour, minute, second", TIME_HMS),
        x if x == fxy(3, 1, 21) => ("Latitude/longitude (high accuracy)", POSITION),
        _ => return None,
    })
}

fn operator_name(x: u16) -> Option<&'static str> {
    Some(match x {
        1 => "Change data width",
        2 => "Change scale",
        3 => "Change reference values",
        4 => "Add associated field",
        5 => "Signify character",
        6 => "Signify data width for the following local descriptor",
        7 => "Increase scale, reference value and data width",
        8 => "Change width of CCITT IA5 field",
        22 => "Quality information follows",
        23 => "Substituted values operator",
        24 => "First-order statistical values follow",
        25 => "Difference statistical values follow",
        32 => "Replaced/retained values follow",
        35 => "Cancel backward data reference",
        36 => "Define data present bit-map",
        37 => "Use defined data present bit-map",
        _ => return None,
    })
}

fn fxy_text(d: u16) -> String {
    format!("{}-{:02}-{:03}", d >> 14, (d >> 8) & 0x3f, d & 0xff)
}

fn describe(d: u16) -> String {
    let (f, x, y) = (d >> 14, (d >> 8) & 0x3f, d & 0xff);
    match f {
        0 => table_b(d).map_or_else(|| "element".to_owned(), |e| e.name.to_owned()),
        1 if y == 0 => format!("Replicate {x} descriptor(s), delayed"),
        1 => format!("Replicate {x} descriptor(s) {y} times"),
        2 => operator_name(x).map_or_else(|| "operator".to_owned(), str::to_owned),
        _ => table_d(d).map_or_else(|| "sequence".to_owned(), |(n, _)| n.to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Messages

#[derive(Clone, Default)]
struct Walk {
    pos: u64,
    index: u64,
    first: Option<String>,
}

const SEARCH_WINDOW: u64 = 64 * 1024;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut w = cx.resume::<Walk>().unwrap_or_default();
    while w.pos < file.len {
        cx.progress_in(file, file.offset.saturating_add(w.pos));
        let head = cx.read_avail(file.sub(w.pos, 8)).await?;
        if !head.starts_with(b"BUFR") {
            let window = cx.read_avail(file.sub(w.pos, SEARCH_WINDOW)).await?;
            match crate::bytes::find(&window, b"BUFR", 0) {
                Some(off) if off > 0 => {
                    let off = to_u64(off);
                    cx.push(
                        Node::new("Gap")
                            .span(file.sub(w.pos, off))
                            .summary(format!("{off} bytes between messages")),
                    )
                    .await;
                    w.pos = w.pos.saturating_add(off);
                    continue;
                }
                _ => {
                    cx.push(Node::new("Trailing data").span(file.tail(w.pos)))
                        .await;
                    break;
                }
            }
        }
        let len = u64::from(crate::bytes::u24_be(&head, 4).unwrap_or(0));
        let edition = head.get(7).copied().unwrap_or(0);
        let index = w.index.saturating_add(1);
        if len < 12 {
            cx.push(
                Node::new(format!("Message {index}"))
                    .span(file.sub(w.pos, 8))
                    .diag(Diagnostic::malformed(format!("message length {len}"))),
            )
            .await;
            break;
        }
        let span = file.sub(w.pos, len);
        let mut node = Node::new(format!("Message {index}")).span(span);
        if (2..=4).contains(&edition) {
            match summarize(&cx, span, edition).await {
                Ok(s) => {
                    if w.first.is_none() {
                        w.first = Some(s.clone());
                    }
                    node = node.summary(s);
                }
                Err(e) => node = node.diag(e),
            }
            node = node.lazy(message, (span, edition));
        } else {
            node = node.diag(Diagnostic::unsupported(format!("BUFR edition {edition}")));
        }
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, span.offset, len),
                span.len,
            ));
        } else if cx.read(span.sub(len.saturating_sub(4), 4)).await? != b"7777" {
            node = node.diag(Diagnostic::malformed("message does not end with 7777"));
        }
        let state = w.clone();
        cx.mark(move || state);
        cx.push(node).await;
        w.index = index;
        w.pos = w.pos.saturating_add(len);
    }
    cx.annotate(match (w.index, w.first) {
        (1, Some(first)) => format!("BUFR, {first}"),
        (n, Some(first)) => format!("{n} BUFR messages, first: {first}"),
        (n, None) => format!("{n} BUFR messages"),
    });
    Ok(())
}

/// What section 1 says, by edition.
struct Ident {
    centre: u64,
    category: u64,
    optional: bool,
    time: (u64, u64, u64, u64, u64),
}

fn ident(b: &[u8], edition: u8) -> Ident {
    let g = |o: usize| u64::from(b.get(o).copied().unwrap_or(0));
    let w = |o: usize| u64::from(crate::bytes::u16_be(b, o).unwrap_or(0));
    match edition {
        4 => Ident {
            centre: w(4),
            category: g(10),
            optional: g(9) & 0x80 != 0,
            time: (w(15), g(17), g(18), g(19), g(20)),
        },
        3 => Ident {
            centre: g(5),
            category: g(8),
            optional: g(7) & 0x80 != 0,
            time: (year_of_century(g(12)), g(13), g(14), g(15), g(16)),
        },
        _ => Ident {
            centre: w(4),
            category: g(8),
            optional: g(7) & 0x80 != 0,
            time: (year_of_century(g(12)), g(13), g(14), g(15), g(16)),
        },
    }
}

/// Editions 2 and 3 store the year of the century; years 00–49 are taken
/// as 2000–2049 (a convention, not part of the format).
fn year_of_century(y: u64) -> u64 {
    if y == 100 {
        2000
    } else if y < 50 {
        2000u64.saturating_add(y)
    } else {
        1900u64.saturating_add(y)
    }
}

async fn summarize(cx: &Cx, span: Span, edition: u8) -> Result<String> {
    let s1 = cx.read_avail(span.sub(8, 24)).await?;
    let id = ident(&s1, edition);
    let s1_len = u64::from(crate::bytes::u24_be(&s1, 0).unwrap_or(0));
    let mut pos = 8u64.saturating_add(s1_len);
    if id.optional {
        let h = cx.read(span.sub(pos, 3)).await?;
        pos = pos.saturating_add(crate::bytes::u24_be(&h, 0).unwrap_or(0).into());
    }
    let s3 = cx.read(span.sub(pos, 7)).await?;
    let s3_len = u64::from(crate::bytes::u24_be(&s3, 0).unwrap_or(0));
    let subsets = crate::bytes::u16_be(&s3, 4).unwrap_or(0);
    let flags = s3.get(6).copied().unwrap_or(0);
    let (y, mo, d, h, mi) = id.time;
    Ok(format!(
        "edition {edition}, {}, {}, {y:04}-{mo:02}-{d:02} {h:02}:{mi:02}, {subsets} subset(s){}, {} descriptor(s)",
        lookup(CENTRES, id.centre).map_or_else(|| format!("centre {}", id.centre), str::to_owned),
        lookup(CATEGORIES, id.category)
            .map_or_else(|| format!("category {}", id.category), str::to_owned),
        if flags & 0x40 != 0 { " compressed" } else { "" },
        s3_len.saturating_sub(7) / 2
    ))
}

async fn message(cx: Cx, (span, edition): (Span, u8)) -> Result<()> {
    cx.emit(struct_node(
        "Section 0: Indicator",
        span.sub(0, 8),
        BE,
        (),
        indicator1,
    ));
    let end = span.len.saturating_sub(4);
    let mut pos = 8u64;
    let mut optional = false;
    let mut subsets = 0u64;
    let mut compressed = false;
    let mut descriptors: Arc<Vec<u16>> = Arc::new(Vec::new());
    for number in 1..=4u8 {
        if number == 2 && !optional {
            continue;
        }
        let name = match number {
            1 => "Section 1: Identification",
            2 => "Section 2: Local data",
            3 => "Section 3: Data description",
            _ => "Section 4: Data",
        };
        if pos.saturating_add(3) > end {
            cx.emit(Node::new(name).diag(Diagnostic::truncated(span.sub(pos, 3), 0)));
            return Ok(());
        }
        let h = cx.read(span.sub(pos, 3)).await?;
        let len = u64::from(crate::bytes::u24_be(&h, 0).unwrap_or(0));
        let sec = span.sub(pos, len);
        if len < 4 || pos.saturating_add(len) > end {
            cx.emit(
                Node::new(name)
                    .span(sec)
                    .diag(Diagnostic::malformed(format!("section length {len}"))),
            );
            return Ok(());
        }
        let node = match number {
            1 => {
                let b = cx.read_avail(sec.sub(0, 24)).await?;
                optional = ident(&b, edition).optional;
                struct_node(name, sec, BE, edition, identification)
            }
            2 => struct_node(name, sec, BE, (), local),
            3 => {
                let b = cx.read(sec).await?;
                subsets = crate::bytes::u16_be(&b, 4).unwrap_or(0).into();
                compressed = b.get(6).copied().unwrap_or(0) & 0x40 != 0;
                descriptors = Arc::new(
                    b.get(7..)
                        .unwrap_or_default()
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_be_bytes(*c))
                        .collect(),
                );
                struct_node(name, sec, BE, (), description)
            }
            _ => {
                let data = sec.tail(4);
                let node = Node::new(name).span(sec).summary(format!("{len} bytes"));
                cx.emit(node.lazy(
                    data_section,
                    (sec, data, descriptors.clone(), subsets, compressed),
                ));
                pos = pos.saturating_add(len);
                continue;
            }
        };
        cx.emit(node.summary(format!("{len} bytes")));
        pos = pos.saturating_add(len);
    }
    if pos < end {
        cx.emit(Node::new("Unaccounted bytes").span(span.sub(pos, end.saturating_sub(pos))));
    }
    cx.emit(
        Node::new("Section 5: End")
            .span(span.sub(end, 4))
            .value(Value::Text("7777".into())),
    );
    Ok(())
}

const SECTION1_FLAGS: crate::value::FlagTable = &[crate::value::flag(0x80, "section 2 present")];

fn identification(f: &mut Fields<'_>, edition: &u8) -> Result<()> {
    u24(f, "Section length")?;
    f.u8("Master table").emit()?;
    match edition {
        4 => {
            f.u16("Originating centre").enumeration(CENTRES).emit()?;
            f.u16("Originating sub-centre").emit()?;
            f.u8("Update sequence number").emit()?;
            f.u8("Flags").flags(SECTION1_FLAGS).emit()?;
            f.u8("Data category").enumeration(CATEGORIES).emit()?;
            f.u8("International data sub-category").emit()?;
            f.u8("Local data sub-category").emit()?;
            f.u8("Master table version").emit()?;
            f.u8("Local table version").emit()?;
            f.u16("Year").emit()?;
            f.u8("Month").emit()?;
            f.u8("Day").emit()?;
            f.u8("Hour").emit()?;
            f.u8("Minute").emit()?;
            f.u8("Second").emit()?;
        }
        3 => {
            f.u8("Originating sub-centre").emit()?;
            f.u8("Originating centre").enumeration(CENTRES).emit()?;
            f.u8("Update sequence number").emit()?;
            f.u8("Flags").flags(SECTION1_FLAGS).emit()?;
            f.u8("Data category").enumeration(CATEGORIES).emit()?;
            f.u8("Data sub-category").emit()?;
            f.u8("Master table version").emit()?;
            f.u8("Local table version").emit()?;
            f.u8("Year of century").emit()?;
            f.u8("Month").emit()?;
            f.u8("Day").emit()?;
            f.u8("Hour").emit()?;
            f.u8("Minute").emit()?;
        }
        _ => {
            f.u16("Originating centre").enumeration(CENTRES).emit()?;
            f.u8("Update sequence number").emit()?;
            f.u8("Flags").flags(SECTION1_FLAGS).emit()?;
            f.u8("Data category").enumeration(CATEGORIES).emit()?;
            f.u8("Data sub-category").emit()?;
            f.u8("Master table version").emit()?;
            f.u8("Local table version").emit()?;
            f.u8("Year of century").emit()?;
            f.u8("Month").emit()?;
            f.u8("Day").emit()?;
            f.u8("Hour").emit()?;
            f.u8("Minute").emit()?;
        }
    }
    rest(f, "Local use / padding")
}

fn local(f: &mut Fields<'_>, _: &()) -> Result<()> {
    u24(f, "Section length")?;
    f.u8("Reserved").emit()?;
    rest(f, "Local data")
}

const SECTION3_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x80, "observed data"),
    crate::value::flag(0x40, "compressed"),
];

fn description(f: &mut Fields<'_>, _: &()) -> Result<()> {
    u24(f, "Section length")?;
    f.u8("Reserved").emit()?;
    f.u16("Number of subsets").emit()?;
    f.u8("Flags").flags(SECTION3_FLAGS).emit()?;
    let n = f.remaining() / 2;
    let span = f.peek_span(n.saturating_mul(2));
    let raw = f.bytes("Descriptors", n.saturating_mul(2)).get()?;
    let list: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect();
    f.node(
        Node::new("Descriptors")
            .span(span)
            .summary(format!("{n} descriptor(s)"))
            .lazy(descriptor_list, (span, Arc::new(list))),
    );
    rest(f, "Padding")
}

async fn descriptor_list(cx: Cx, (span, list): (Span, Arc<Vec<u16>>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(list.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, &d) in list.iter().enumerate().skip(start) {
        cx.mark(move || i);
        let mut node = Node::new(fxy_text(d))
            .span(span.sub(to_u64(i).saturating_mul(2), 2))
            .value(Value::Text(describe(d)));
        if let Some((_, seq)) = table_d(d) {
            let parts: Vec<String> = seq.iter().map(|&x| fxy_text(x)).collect();
            node = node.summary(parts.join(" "));
        } else if let Some(e) = table_b(d) {
            node = node.summary(format!(
                "{}{}scale {}, reference {}, {} bits",
                e.unit,
                if e.unit.is_empty() { "" } else { ", " },
                e.scale,
                e.reference,
                e.width
            ));
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Data decoding

/// One decoded element: its descriptor, bit range within section 4's data,
/// and value per subset (one value unless compressed).
#[derive(Debug)]
struct Slot {
    desc: u16,
    bits: (u64, u64),
    values: Vec<Option<f64>>,
}

const MAX_SLOTS: usize = 100_000;
const MAX_DEPTH: u8 = 16;

struct Decoder<'a> {
    cx: &'a Cx,
    data: &'a [u8],
    bit: u64,
    compressed: bool,
    subsets: u64,
    width_delta: i32,
    scale_delta: i32,
    slots: Vec<Slot>,
    /// Descriptors processed and values stored so far, to bound the work
    /// of (nested, possibly empty) replications.
    steps: u64,
    values: u64,
    /// Work (descriptors, bits read, values copied) since the last
    /// checkpoint, and the furthest bit any element ends at.
    work: u64,
    used: u64,
}

/// Work counted per unit charged: a descriptor or a value counts one, as
/// does each bit read.
const WORK_PER_UNIT: u64 = 1024;

type RunFuture<'s> = Pin<Box<dyn Future<Output = Result<()>> + Send + 's>>;

const MAX_STEPS: u64 = 1_000_000;
const MAX_VALUES: u64 = 2_000_000;

fn take(data: &[u8], at: u64, n: u16) -> Option<u64> {
    if n > 64 {
        return None;
    }
    let mut v = 0u64;
    for i in 0..u64::from(n) {
        let bit = at.checked_add(i)?;
        let byte = *data.get(usize::try_from(bit / 8).ok()?)?;
        let shift = 7u64.saturating_sub(bit % 8);
        v = v.checked_shl(1).unwrap_or(0) | u64::from((byte >> shift) & 1);
    }
    Some(v)
}

fn all_ones(v: u64, width: u16) -> bool {
    width > 0 && width <= 64 && v == u64::MAX >> 64u16.saturating_sub(width)
}

impl<'a> Decoder<'a> {
    /// Counts `n` of work, charging a unit every [`WORK_PER_UNIT`].
    async fn tick(&mut self, n: u64) {
        self.work = self.work.saturating_add(n);
        while self.work >= WORK_PER_UNIT {
            self.work = self.work.saturating_sub(WORK_PER_UNIT);
            self.cx.checkpoint().await;
        }
    }

    fn bits(&mut self, n: u16) -> Result<u64> {
        let v = take(self.data, self.bit, n).ok_or_else(|| {
            Diagnostic::malformed(format!("data ends inside an element at bit {}", self.bit))
        })?;
        self.bit = self.bit.saturating_add(n.into());
        Ok(v)
    }

    fn element(&mut self, d: u16) -> Result<Vec<Option<f64>>> {
        let def = table_b(d).ok_or_else(|| {
            Diagnostic::unsupported(format!(
                "descriptor {} is not in the built-in Table B",
                fxy_text(d)
            ))
        })?;
        // The 2-01/2-02 operators do not apply to the replication factors.
        let (dw, ds) = if (d >> 8) & 0x3f == 31 {
            (0, 0)
        } else {
            (self.width_delta, self.scale_delta)
        };
        let width = u16::try_from(i32::from(def.width).saturating_add(dw))
            .map_err(|_| Diagnostic::malformed("negative data width"))?;
        let scale = def.scale.saturating_add(ds);
        let value = |raw: u64| -> Option<f64> {
            if all_ones(raw, width) && (d >> 8) & 0x3f != 31 {
                None
            } else {
                Some((raw as f64 + def.reference as f64) / 10f64.powi(scale))
            }
        };
        if !self.compressed {
            let raw = self.bits(width)?;
            return Ok(vec![value(raw)]);
        }
        let r0 = self.bits(width)?;
        let nbinc = u16::try_from(self.bits(6)?).unwrap_or(0);
        if nbinc == 0 {
            let v = value(r0);
            return Ok(vec![v; usize::try_from(self.subsets).unwrap_or(0)]);
        }
        let mut out = Vec::new();
        for _ in 0..self.subsets {
            let inc = self.bits(nbinc)?;
            out.push(if all_ones(inc, nbinc) || all_ones(r0, width) {
                None
            } else {
                value(r0.saturating_add(inc))
            });
        }
        Ok(out)
    }

    fn push(&mut self, desc: u16, start: u64, values: Vec<Option<f64>>) -> Result<()> {
        self.values = self.values.saturating_add(to_u64(values.len()));
        if self.slots.len() >= MAX_SLOTS || self.values > MAX_VALUES {
            return Err(Diagnostic::limit(format!("more than {MAX_SLOTS} elements")));
        }
        self.slots.push(Slot {
            desc,
            bits: (start, self.bit),
            values,
        });
        self.used = self.used.max(self.bit);
        Ok(())
    }

    fn run_boxed<'s>(&'s mut self, descs: &'s [u16], depth: u8) -> RunFuture<'s>
    where
        'a: 's,
    {
        Box::pin(self.run(descs, depth))
    }

    async fn run(&mut self, descs: &[u16], depth: u8) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("descriptors nested too deeply"));
        }
        let mut i = 0usize;
        while let Some(&d) = descs.get(i) {
            self.steps = self.steps.saturating_add(1);
            if self.steps > MAX_STEPS {
                return Err(Diagnostic::limit("descriptor expansion too long"));
            }
            let before = self.bit;
            let values = self.values;
            self.tick(1).await;
            let (f, x, y) = (d >> 14, (d >> 8) & 0x3f, d & 0xff);
            match f {
                0 => {
                    let start = self.bit;
                    let v = self.element(d)?;
                    self.push(d, start, v)?;
                    i = i.saturating_add(1);
                }
                1 => {
                    let count = usize::from(x);
                    let (factor, group_at) = if y == 0 {
                        let rd = *descs.get(i.saturating_add(1)).ok_or_else(|| {
                            Diagnostic::malformed("delayed replication without a factor")
                        })?;
                        let start = self.bit;
                        let v = self.element(rd)?;
                        let factor = v.first().copied().flatten().unwrap_or(0.0);
                        self.push(rd, start, v)?;
                        (factor as u64, i.saturating_add(2))
                    } else {
                        (u64::from(y), i.saturating_add(1))
                    };
                    let group = descs
                        .get(group_at..group_at.saturating_add(count))
                        .ok_or_else(|| Diagnostic::malformed("replication past the end"))?;
                    if !group.is_empty() {
                        for _ in 0..factor {
                            self.run_boxed(group, depth.saturating_add(1)).await?;
                        }
                    }
                    i = group_at.saturating_add(count);
                }
                2 => {
                    let delta = if y == 0 {
                        0
                    } else {
                        i32::from(y).saturating_sub(128)
                    };
                    match x {
                        1 => self.width_delta = delta,
                        2 => self.scale_delta = delta,
                        _ => {
                            return Err(Diagnostic::unsupported(format!(
                                "operator {}",
                                fxy_text(d)
                            )));
                        }
                    }
                    i = i.saturating_add(1);
                }
                _ => {
                    let (_, seq) = table_d(d).ok_or_else(|| {
                        Diagnostic::unsupported(format!(
                            "sequence {} is not in the built-in Table D",
                            fxy_text(d)
                        ))
                    })?;
                    self.run_boxed(seq, depth.saturating_add(1)).await?;
                    i = i.saturating_add(1);
                }
            }
            if f == 0 || (f == 1 && y == 0) {
                let read = self.bit.saturating_sub(before);
                let stored = self.values.saturating_sub(values);
                self.tick(read.saturating_add(stored)).await;
            }
        }
        Ok(())
    }
}

/// Decoded subsets: per subset, its elements (descriptor, bit range, value).
type Subset = Vec<(u16, (u64, u64), Option<f64>)>;

/// Decodes the subsets, and the furthest bit any element ends at.
async fn decode(
    cx: &Cx,
    data: &[u8],
    descs: &[u16],
    subsets: u64,
    compressed: bool,
) -> Result<(Vec<Subset>, u64)> {
    let mut d = Decoder {
        cx,
        data,
        bit: 0,
        compressed,
        subsets,
        width_delta: 0,
        scale_delta: 0,
        slots: Vec::new(),
        steps: 0,
        values: 0,
        work: 0,
        used: 0,
    };
    if compressed {
        d.run(descs, 0).await?;
        let mut out = Vec::new();
        for s in 0..usize::try_from(subsets).unwrap_or(0) {
            d.tick(to_u64(d.slots.len())).await;
            out.push(
                d.slots
                    .iter()
                    .map(|slot| (slot.desc, slot.bits, slot.values.get(s).copied().flatten()))
                    .collect(),
            );
        }
        let used = if out.is_empty() { 0 } else { d.used };
        return Ok((out, used));
    }
    let mut out = Vec::new();
    for _ in 0..subsets {
        d.slots.clear();
        d.width_delta = 0;
        d.scale_delta = 0;
        d.run(descs, 0).await?;
        d.tick(to_u64(d.slots.len())).await;
        out.push(
            d.slots
                .iter()
                .map(|slot| (slot.desc, slot.bits, slot.values.first().copied().flatten()))
                .collect(),
        );
        if out.len().saturating_mul(d.slots.len().max(1)) > MAX_SLOTS {
            return Err(Diagnostic::limit(format!("more than {MAX_SLOTS} elements")));
        }
    }
    let used = if out.is_empty() { 0 } else { d.used };
    Ok((out, used))
}

type DataState = (Span, Span, Arc<Vec<u16>>, u64, bool);

async fn data_section(cx: Cx, (sec, data, descs, subsets, compressed): DataState) -> Result<()> {
    let head = cx.block(sec.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    u24(&mut f, "Section length")?;
    f.u8("Reserved").emit()?;
    let bytes = cx.read(data).await?;
    match decode(&cx, &bytes, &descs, subsets, compressed).await {
        Ok((decoded, used)) => {
            cx.emit(
                Node::new("Subsets")
                    .span(data)
                    .summary(format!(
                        "{} subset(s), {} of {} bits used",
                        decoded.len(),
                        used,
                        data.len.saturating_mul(8)
                    ))
                    .lazy(subset_list, (data, Arc::new(decoded))),
            );
        }
        Err(e) => {
            cx.emit(Node::new("Packed data").span(data).diag(e));
        }
    }
    Ok(())
}

async fn subset_list(cx: Cx, (data, subsets): (Span, Arc<Vec<Subset>>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(subsets.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, s) in subsets.iter().enumerate().skip(start) {
        cx.mark(move || i);
        let first = s.iter().map(|e| e.1.0).min().unwrap_or(0);
        let last = s.iter().map(|e| e.1.1).max().unwrap_or(0);
        let span = data.sub(first / 8, last.div_ceil(8).saturating_sub(first / 8));
        let preview: Vec<String> = s
            .iter()
            .filter(|e| (e.0 >> 8) & 0x3f != 31)
            .take(4)
            .map(|e| e.2.map_or_else(|| "missing".to_owned(), num))
            .collect();
        cx.push(
            Node::new(format!("Subset {}", i.saturating_add(1)))
                .span(span)
                .summary(format!("{} elements: {} …", s.len(), preview.join(", ")))
                .lazy(subset, (data, subsets.clone(), i)),
        )
        .await;
    }
    Ok(())
}

async fn subset(cx: Cx, (data, subsets, index): (Span, Arc<Vec<Subset>>, usize)) -> Result<()> {
    let Some(s) = subsets.get(index) else {
        return Ok(());
    };
    cx.set_count(Count::Exact(to_u64(s.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, &(desc, (from, to), value)) in s.iter().enumerate().skip(start) {
        cx.mark(move || i);
        let def = table_b(desc);
        let name = def.as_ref().map_or("element", |d| d.name);
        let unit = def.as_ref().map_or("", |d| d.unit);
        let span = data.sub(from / 8, to.div_ceil(8).saturating_sub(from / 8));
        let mut node = Node::new(name).span(span);
        node = match value {
            Some(v) => node.value(Value::Float(v)),
            None => node.value(Value::Text("missing".into())),
        };
        node = node.summary(if unit.is_empty() || unit == "code table" {
            fxy_text(desc)
        } else {
            format!("{unit}, {}", fxy_text(desc))
        });
        cx.push(node).await;
    }
    Ok(())
}
