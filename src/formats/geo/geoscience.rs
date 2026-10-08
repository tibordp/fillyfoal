//! Geoscience and remote-sensing formats: seismic data (SEG-Y, SEG-2,
//! miniSEED 2 and 3, SAC), rasters and grids (ERDAS IMAGINE, Surfer, ESRI
//! ASCII grid, ENVI headers, PDS3 labels, VICAR), point clouds (E57, PCD)
//! and well logs (LAS).

use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_be, u32_le};
use crate::codec::crc::crc32c;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{
    Line, Lines, enumeration, float32, head_lines, int, is_text, number, preview, summarize, text,
    uint,
};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// SEG-Y

/// EBCDIC (code page 037) to ASCII; unprintable bytes become '.'.
const EBCDIC: [u8; 256] = [
    46, 46, 46, 46, 46, 32, 46, 46, 46, 46, 46, 46, 46, 32, 46, 46, 46, 46, 46, 46, 46, 32, 46, 46,
    46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 32, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46,
    46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 32, 46, 46, 46, 46, 46, 46, 46,
    46, 46, 46, 46, 60, 40, 43, 124, 38, 46, 46, 46, 46, 46, 46, 46, 46, 46, 33, 36, 42, 41, 59,
    46, 45, 47, 46, 46, 46, 46, 46, 46, 46, 46, 46, 44, 37, 95, 62, 63, 46, 46, 46, 46, 46, 46, 46,
    46, 46, 96, 58, 35, 64, 39, 61, 34, 46, 97, 98, 99, 100, 101, 102, 103, 104, 105, 46, 46, 46,
    46, 46, 46, 46, 106, 107, 108, 109, 110, 111, 112, 113, 114, 46, 46, 46, 46, 46, 46, 46, 126,
    115, 116, 117, 118, 119, 120, 121, 122, 46, 46, 46, 46, 46, 46, 94, 46, 46, 46, 46, 46, 46, 46,
    46, 46, 91, 93, 46, 46, 46, 46, 123, 65, 66, 67, 68, 69, 70, 71, 72, 73, 46, 46, 46, 46, 46,
    46, 125, 74, 75, 76, 77, 78, 79, 80, 81, 82, 46, 46, 46, 46, 46, 46, 92, 46, 83, 84, 85, 86,
    87, 88, 89, 90, 46, 46, 46, 46, 46, 46, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 46, 46, 46, 46,
    46, 46,
];

fn ebcdic(b: &[u8]) -> String {
    b.iter()
        .map(|&c| char::from(EBCDIC.get(usize::from(c)).copied().unwrap_or(b'.')))
        .collect()
}

const SEGY_FORMATS: EnumTable = &[
    (1, "IBM float32"),
    (2, "int32"),
    (3, "int16"),
    (4, "fixed point with gain (obsolete)"),
    (5, "IEEE float32"),
    (6, "IEEE float64"),
    (7, "int24"),
    (8, "int8"),
    (9, "int64"),
    (10, "uint32"),
    (11, "uint16"),
    (12, "uint64"),
    (15, "uint24"),
    (16, "uint8"),
];

fn segy_sample_size(format: u16) -> u64 {
    match format {
        1 | 2 | 4 | 5 | 10 => 4,
        3 | 11 => 2,
        6 | 9 | 12 => 8,
        7 | 15 => 3,
        8 | 16 => 1,
        _ => 0,
    }
}

fn segy_probe(h: &Head<'_>) -> bool {
    let format = u16_be(h.data, 3224).unwrap_or(0);
    let cards = (h.at(0, b"\xc3") && h.data.get(80) == Some(&0xc3))
        || (h.at(0, b"C") && h.data.get(80) == Some(&b'C'));
    cards && segy_sample_size(format) > 0 && u16_be(h.data, 3220).is_some_and(|n| n > 0)
}

declare_format!(pub SEGY = "segy", "SEG-Y seismic data", ["segy", "sgy", "seg"], "application/x-segy",
    Probe::Custom(segy_probe), segy);

const SEGY_SORTING: EnumTable = &[
    (0xffff, "other"),
    (0, "unknown"),
    (1, "as recorded"),
    (2, "CDP ensemble"),
    (3, "single fold continuous profile"),
    (4, "horizontally stacked"),
    (5, "common source point"),
    (6, "common receiver point"),
    (7, "common offset point"),
    (8, "common mid-point"),
    (9, "common conversion point"),
];
const SEGY_UNITS: EnumTable = &[(1, "meters"), (2, "feet")];

record! {
    pub struct SegyBinary {
        job: i32 "Job ID",
        line: i32 "Line number",
        reel: i32 "Reel number",
        traces: u16 "Data traces per ensemble",
        aux: u16 "Auxiliary traces per ensemble",
        interval: u16 "Sample interval (µs)",
        original_interval: u16 "Original sample interval (µs)",
        samples: u16 "Samples per trace",
        original_samples: u16 "Original samples per trace",
        format: u16 "Data sample format" .enumeration(SEGY_FORMATS),
        fold: u16 "Ensemble fold",
        sorting: u16 "Trace sorting" .enumeration(SEGY_SORTING),
        vertical_sum: u16 "Vertical sum code",
        sweep: bytes[22] "Sweep parameters",
        units: u16 "Measurement system" .enumeration(SEGY_UNITS),
        polarity: u16 "Impulse signal polarity",
        vibratory: u16 "Vibratory polarity code",
    }
}

/// IBM System/360 single-precision float.
fn ibm_float(v: u32) -> f64 {
    let sign = if v >> 31 == 0 { 1.0 } else { -1.0 };
    let exponent = i32::try_from((v >> 24) & 0x7f)
        .unwrap_or(64)
        .saturating_sub(64);
    let fraction = f64::from(v & 0x00ff_ffff) / 16_777_216.0;
    sign * fraction * 16f64.powi(exponent)
}

fn segy_sample(b: &[u8], format: u16) -> f64 {
    match format {
        1 => ibm_float(u32_be(b, 0).unwrap_or(0)),
        2 => f64::from(crate::bytes::i32_be(b, 0).unwrap_or(0)),
        3 => f64::from(u16_be(b, 0).unwrap_or(0).cast_signed()),
        5 => f64::from(f32::from_bits(u32_be(b, 0).unwrap_or(0))),
        6 => f64::from_bits(crate::bytes::u64_be(b, 0).unwrap_or(0)),
        8 => f64::from(b.first().copied().unwrap_or(0).cast_signed()),
        10 => f64::from(u32_be(b, 0).unwrap_or(0)),
        11 => f64::from(u16_be(b, 0).unwrap_or(0)),
        16 => f64::from(b.first().copied().unwrap_or(0)),
        _ => 0.0,
    }
}

async fn segy(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let cards = cx.read_avail(file.sub(0, 3200)).await?;
    let is_ebcdic = cards.first() == Some(&0xc3);
    let decoded: Vec<String> = cards
        .chunks(80)
        .map(|c| {
            if is_ebcdic {
                ebcdic(c)
            } else {
                String::from_utf8_lossy(c).into_owned()
            }
        })
        .collect();
    let first = decoded
        .first()
        .map(|c| c.get(3..).unwrap_or_default().trim().to_owned())
        .unwrap_or_default();
    cx.emit(
        Node::new("Textual header")
            .span(file.sub(0, 3200))
            .summary(format!(
                "{}, {}",
                if is_ebcdic { "EBCDIC" } else { "ASCII" },
                preview(&first, 60)
            ))
            .lazy(segy_cards, (file.sub(0, 3200), decoded)),
    );
    let bspan = file.sub(3200, 400);
    let b: SegyBinary = read_record(&cx, bspan.sub(0, SegyBinary::SIZE), BE).await?;
    cx.emit(
        Node::new("Binary header")
            .span(bspan)
            .summary(format!(
                "{} samples × {} µs, {}",
                b.samples,
                b.interval,
                lookup(SEGY_FORMATS, b.format.into()).unwrap_or("?")
            ))
            .lazy(segy_binary, bspan),
    );
    let rev = cx.read_avail(bspan.sub(300, 6)).await?;
    let revision = u16_be(&rev, 0).unwrap_or(0);
    let extended = u16_be(&rev, 4).unwrap_or(0).cast_signed().max(0);
    let ext_span = file.sub(
        3600,
        u64::from(extended.unsigned_abs()).saturating_mul(3200),
    );
    if extended > 0 {
        cx.emit(
            Node::new("Extended textual headers")
                .span(ext_span)
                .value(uint(extended.unsigned_abs().into())),
        );
    }
    let traces = file.tail(3600u64.saturating_add(ext_span.len));
    let size = segy_sample_size(b.format);
    let trace_len = 240u64.saturating_add(u64::from(b.samples).saturating_mul(size));
    let count = traces.len.checked_div(trace_len).unwrap_or(0);
    cx.emit(
        Node::new("Traces")
            .span(traces)
            .value(uint(count))
            .lazy(segy_traces, (traces, b.format, b.samples)),
    );
    cx.annotate(format!(
        "SEG-Y rev {}.{}, {count} trace(s) × {} samples at {} µs ({}){}",
        revision >> 8,
        revision & 0xff,
        b.samples,
        b.interval,
        lookup(SEGY_FORMATS, b.format.into()).unwrap_or("?"),
        if first.is_empty() {
            String::new()
        } else {
            format!("; {}", preview(&first, 50))
        }
    ));
    Ok(())
}

async fn segy_cards(cx: Cx, (span, cards): (Span, Vec<String>)) -> Result<()> {
    for (i, c) in cards.into_iter().enumerate() {
        // Blank cards are padding.
        if c.trim().is_empty() {
            continue;
        }
        cx.push(
            Node::new(format!("Card {}", i.saturating_add(1)))
                .span(span.sub(to_u64(i).saturating_mul(80), 80))
                .value(text(c.trim_end())),
        )
        .await;
    }
    Ok(())
}

async fn segy_binary(cx: Cx, span: Span) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &b, BE);
    SegyBinary::read(&mut f)?;
    f.seek(300);
    f.u16("SEG-Y revision").hex().emit()?;
    f.u16("Fixed length trace flag").emit()?;
    f.u16("Extended textual headers").emit()?;
    Ok(())
}

record! {
    pub struct SegyTrace {
        line_seq: i32 "Trace sequence number in line",
        file_seq: i32 "Trace sequence number in file",
        field_record: i32 "Original field record number",
        trace: i32 "Trace number in field record",
        source: i32 "Energy source point number",
        ensemble: i32 "Ensemble number",
        ensemble_trace: i32 "Trace number in ensemble",
        id: u16 "Trace identification code",
        vertical: u16 "Vertically summed traces",
        horizontal: u16 "Horizontally stacked traces",
        usage: u16 "Data use",
        offset: i32 "Source-receiver offset",
        receiver_elevation: i32 "Receiver group elevation",
        source_elevation: i32 "Surface elevation at source",
        source_depth: i32 "Source depth below surface",
        datum_receiver: i32 "Datum elevation at receiver",
        datum_source: i32 "Datum elevation at source",
        water_source: i32 "Water depth at source",
        water_group: i32 "Water depth at group",
        elevation_scalar: i16 "Elevation scalar",
        coordinate_scalar: i16 "Coordinate scalar",
        source_x: i32 "Source X",
        source_y: i32 "Source Y",
        group_x: i32 "Group X",
        group_y: i32 "Group Y",
        coordinate_units: u16 "Coordinate units",
    }
}

async fn segy_traces(cx: Cx, (span, format, samples): (Span, u16, u16)) -> Result<()> {
    let size = segy_sample_size(format);
    let mut at = 0u64;
    let mut i = 0u64;
    while at.saturating_add(240) <= span.len {
        cx.progress_in(span, span.offset.saturating_add(at));
        let head = cx.read(span.sub(at, 240)).await?;
        // Per-trace sample counts take precedence when set.
        let n = match u16_be(&head, 114) {
            Some(n) if n > 0 => n,
            _ => samples,
        };
        let len = 240u64.saturating_add(u64::from(n).saturating_mul(size));
        let trace = span.sub(at, len);
        let t: SegyTrace = read_record(&cx, trace.sub(0, SegyTrace::SIZE), BE).await?;
        let data = cx
            .read_avail(trace.sub(240, size.saturating_mul(6)))
            .await?;
        let shown: Vec<String> = data
            .chunks(to_usize(size).max(1))
            .filter(|c| to_u64(c.len()) == size)
            .map(|c| format!("{:.4}", segy_sample(c, format)))
            .collect();
        cx.push(
            Node::new(format!("Trace {i}"))
                .span(trace)
                .summary(format!(
                    "field record {}, trace {}, CDP {}, {n} samples: {}{}",
                    t.field_record,
                    t.trace,
                    t.ensemble,
                    shown.join(", "),
                    if n > 6 { ", …" } else { "" }
                ))
                .lazy(segy_trace, (trace, format)),
        )
        .await;
        at = at.saturating_add(len);
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn segy_trace(cx: Cx, (trace, format): (Span, u16)) -> Result<()> {
    cx.emit(SegyTrace::node("Trace header", trace.sub(0, 240), BE));
    let h = cx.read_avail(trace.sub(114, 4)).await?;
    cx.emit(
        Node::new("Samples in trace")
            .span(trace.sub(114, 2))
            .value(uint(u16_be(&h, 0).unwrap_or(0).into())),
    );
    cx.emit(
        Node::new("Sample interval (µs)")
            .span(trace.sub(116, 2))
            .value(uint(u16_be(&h, 2).unwrap_or(0).into())),
    );
    cx.emit(
        Node::new("Samples").span(trace.tail(240)).summary(
            lookup(SEGY_FORMATS, format.into())
                .unwrap_or("?")
                .to_owned(),
        ),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// SEG-2

fn seg2_probe(h: &Head<'_>) -> bool {
    (h.at(0, b"\x55\x3a")
        && u16_le(h.data, 2) == Some(1)
        && u16_le(h.data, 4).is_some_and(|m| m % 4 == 0 && m > 0))
        || (h.at(0, b"\x3a\x55")
            && u16_be(h.data, 2) == Some(1)
            && u16_be(h.data, 4).is_some_and(|m| m % 4 == 0 && m > 0))
}

declare_format!(pub SEG2 = "seg2", "SEG-2 seismic data", ["seg2", "sg2", "dat"], "application/x-seg2",
    Probe::Custom(seg2_probe), seg2);

const SEG2_FORMATS: EnumTable = &[
    (1, "int16"),
    (2, "int32"),
    (3, "20-bit packed"),
    (4, "float32"),
    (5, "float64"),
];

/// The free-form strings of a SEG-2 block: each has a u16 length prefix.
async fn seg2_strings(cx: &Cx, span: Span, endian: Endian) -> Result<Vec<(String, Span)>> {
    let mut cur = Cursor::new(cx, span, endian);
    let mut out = Vec::new();
    while cur.remaining() >= 2 {
        let start = cur.pos();
        let len = cur.u16().await?;
        if len < 2 {
            break;
        }
        let body = cur.bytes(u64::from(len).saturating_sub(2)).await?;
        let s = crate::text::until_nul(&body);
        if !s.trim().is_empty() {
            out.push((s.trim().to_owned(), span.sub(start, len.into())));
        }
        if out.len() > 10_000 {
            break;
        }
    }
    Ok(out)
}

async fn seg2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let endian = if cx.read(file.sub(0, 2)).await? == b"\x55\x3a" {
        LE
    } else {
        BE
    };
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, endian);
    f.u16("Block ID").hex().emit()?;
    let revision = f.u16("Revision").emit()?;
    let m = f.u16("Trace pointer subblock size").emit()?;
    let n = f.u16("Number of traces").emit()?;
    f.u8("String terminator length").emit()?;
    f.bytes("String terminator", 2).emit()?;
    f.u8("Line terminator length").emit()?;
    f.bytes("Line terminator", 2).emit()?;
    let pointers = file.sub(32, m.into());
    let raw = cx.read_avail(pointers).await?;
    let offsets: Vec<u64> = raw
        .as_chunks::<4>()
        .0
        .iter()
        .take(n.into())
        .map(|c| {
            u64::from(if endian == LE {
                u32::from_le_bytes(*c)
            } else {
                u32::from_be_bytes(*c)
            })
        })
        .collect();
    let strings_at = 32u64.saturating_add(m.into());
    let strings_end = offsets
        .iter()
        .copied()
        .filter(|&o| o > strings_at)
        .min()
        .unwrap_or(file.len);
    let strings = file.sub(strings_at, strings_end.saturating_sub(strings_at));
    let list = seg2_strings(&cx, strings, endian).await?;
    cx.emit(
        Node::new("Trace pointers")
            .span(pointers)
            .value(uint(n.into())),
    );
    cx.emit(
        Node::new("File descriptor strings")
            .span(strings)
            .value(uint(to_u64(list.len())))
            .lazy(seg2_string_list, list.clone()),
    );
    cx.emit(Node::new("Traces").lazy(seg2_traces, (file, offsets, endian)));
    let date = list
        .iter()
        .find(|(s, _)| s.starts_with("ACQUISITION_DATE"))
        .map(|(s, _)| s.trim_start_matches("ACQUISITION_DATE").trim().to_owned())
        .unwrap_or_default();
    cx.annotate(format!(
        "SEG-2 rev {revision}, {n} trace(s){}",
        if date.is_empty() {
            String::new()
        } else {
            format!(", acquired {date}")
        }
    ));
    Ok(())
}

async fn seg2_string_list(cx: Cx, list: Vec<(String, Span)>) -> Result<()> {
    for (s, span) in list {
        let (k, v) = s
            .split_once(char::is_whitespace)
            .unwrap_or((s.as_str(), ""));
        cx.push(Node::new(k.to_owned()).span(span).value(number(v.trim())))
            .await;
    }
    Ok(())
}

async fn seg2_traces(cx: Cx, (file, offsets, endian): (Span, Vec<u64>, Endian)) -> Result<()> {
    for (i, &o) in offsets.iter().enumerate() {
        let b = cx.block(file.sub(o, 32)).await?;
        let mut f = Fields::new(&b, endian);
        let id = f.u16("Block ID").get()?;
        let size = f.u16("Block size").get()?;
        let data = f.u32("Data size").get()?;
        let samples = f.u32("Samples").get()?;
        let format = f.u8("Format").get()?;
        let span = file.sub(o, u64::from(size).saturating_add(data.into()));
        let mut node = Node::new(format!("Trace {i}"))
            .span(span)
            .summary(format!(
                "{samples} samples, {}",
                lookup(SEG2_FORMATS, format.into()).unwrap_or("?")
            ))
            .lazy(
                seg2_trace,
                (
                    file.sub(o, size.into()),
                    file.sub(o.saturating_add(size.into()), data.into()),
                    endian,
                ),
            );
        if id != 0x4422 {
            node = node.diag(Diagnostic::malformed(format!(
                "trace descriptor ID {id:#x}"
            )));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn seg2_trace(cx: Cx, (desc, data, endian): (Span, Span, Endian)) -> Result<()> {
    let b = cx.block(desc.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &b, endian);
    f.u16("Block ID").hex().emit()?;
    f.u16("Block size").emit()?;
    f.u32("Data size").emit()?;
    f.u32("Samples").emit()?;
    f.u8("Data format").enumeration(SEG2_FORMATS).emit()?;
    let list = seg2_strings(&cx, desc.tail(32), endian).await?;
    cx.emit(
        Node::new("Strings")
            .span(desc.tail(32))
            .value(uint(to_u64(list.len())))
            .lazy(seg2_string_list, list),
    );
    cx.emit(Node::new("Data").span(data));
    Ok(())
}

// ---------------------------------------------------------------------------
// miniSEED 2 and 3

fn mseed2_endian(h: &[u8]) -> Option<Endian> {
    let ok = |y: u16, d: u16| (1900..=2100).contains(&y) && (1..=366).contains(&d);
    if ok(u16_be(h, 20)?, u16_be(h, 22)?) {
        Some(BE)
    } else if ok(u16_le(h, 20)?, u16_le(h, 22)?) {
        Some(LE)
    } else {
        None
    }
}

fn mseed2_probe(h: &Head<'_>) -> bool {
    let seq = h.data.get(..6).unwrap_or_default();
    seq.len() == 6
        && seq
            .iter()
            .all(|&b| b.is_ascii_digit() || b == b' ' || b == 0)
        && seq.iter().any(u8::is_ascii_digit)
        && h.data.get(6).is_some_and(|b| b"DRQM".contains(b))
        && h.data.get(7).is_some_and(|&b| b == b' ' || b == 0)
        && h.data.get(8..20).is_some_and(|id| {
            id.iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b' ' || b == b'-' || b == 0)
        })
        && mseed2_endian(h.data).is_some()
}

declare_format!(pub MSEED2 = "miniseed", "miniSEED (SEED 2.x data records)", ["mseed", "miniseed", "msd"], "application/vnd.fdsn.mseed",
    Probe::Custom(mseed2_probe), mseed2);
declare_format!(pub MSEED3 = "miniseed3", "miniSEED 3", ["ms3", "mseed3"], "application/vnd.fdsn.mseed3",
    Probe::Custom(|h| h.at(0, b"MS\x03") && h.data.get(12).is_some_and(|&hh| hh < 24)), mseed3);

const MSEED_ENCODINGS: EnumTable = &[
    (0, "ASCII text"),
    (1, "int16"),
    (2, "int24"),
    (3, "int32"),
    (4, "float32"),
    (5, "float64"),
    (10, "Steim-1"),
    (11, "Steim-2"),
    (12, "GEOSCOPE 24-bit"),
    (13, "GEOSCOPE 16/3"),
    (14, "GEOSCOPE 16/4"),
    (15, "USNSN"),
    (16, "CDSN"),
    (17, "Graefenberg"),
    (18, "IPG Strasbourg"),
    (19, "Steim-3"),
    (30, "SRO"),
    (31, "HGLP"),
    (32, "DWWSSN"),
    (33, "RSTN 16-bit"),
    (100, "opaque"),
];

record! {
    pub struct MseedHeader {
        sequence: ascii[6] "Sequence number",
        quality: ascii[1] "Data quality",
        reserved: ascii[1] "Reserved",
        station: ascii[5] "Station",
        location: ascii[2] "Location",
        channel: ascii[3] "Channel",
        network: ascii[2] "Network",
        year: u16 "Year",
        day: u16 "Day of year",
        hour: u8 "Hour",
        minute: u8 "Minute",
        second: u8 "Second",
        unused: u8 "Unused",
        fraction: u16 "Fraction (0.0001 s)",
        samples: u16 "Number of samples",
        rate_factor: i16 "Sample rate factor",
        rate_multiplier: i16 "Sample rate multiplier",
        activity: u8 "Activity flags" .hex(),
        io: u8 "I/O flags" .hex(),
        quality_flags: u8 "Data quality flags" .hex(),
        blockettes: u8 "Number of blockettes",
        correction: i32 "Time correction (0.0001 s)",
        data_offset: u16 "Beginning of data",
        first_blockette: u16 "First blockette",
    }
}

fn sample_rate(factor: i16, multiplier: i16) -> f64 {
    let (f, m) = (f64::from(factor), f64::from(multiplier));
    match (factor > 0, multiplier > 0) {
        _ if factor == 0 => 0.0,
        (true, true) => f * m,
        (true, false) if multiplier != 0 => -f / m,
        (false, true) => -m / f,
        (false, false) if multiplier != 0 => 1.0 / (f * m),
        _ => f,
    }
}

fn source_id(h: &MseedHeader) -> String {
    format!(
        "{}.{}.{}.{}",
        h.network.trim(),
        h.station.trim(),
        h.location.trim(),
        h.channel.trim()
    )
}

async fn mseed2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let first = cx.read(file.sub(0, 48)).await?;
    let endian = mseed2_endian(&first).unwrap_or(BE);
    let mut at = 0u64;
    let mut count = 0u64;
    let mut ids: Vec<String> = Vec::new();
    let mut samples = 0u64;
    while at.saturating_add(48) <= file.len {
        cx.progress_in(file, file.offset.saturating_add(at));
        let h: MseedHeader = read_record(&cx, file.sub(at, MseedHeader::SIZE), endian).await?;
        // Blockette 1000 gives the record length; walk the blockette chain.
        let mut len = 0u64;
        let mut encoding = None;
        let mut next = u64::from(h.first_blockette);
        let mut guard = 0u32;
        while next >= 48 && guard < 32 {
            let b = cx.read_avail(file.sub(at.saturating_add(next), 8)).await?;
            let read16 = |o: usize| {
                if endian == LE {
                    u16_le(&b, o)
                } else {
                    u16_be(&b, o)
                }
            };
            let (Some(kind), Some(after)) = (read16(0), read16(2)) else {
                break;
            };
            if kind == 1000 {
                encoding = b.get(4).copied();
                len = 1u64
                    .checked_shl(b.get(6).copied().unwrap_or(12).into())
                    .unwrap_or(4096);
            }
            if u64::from(after) <= next {
                break;
            }
            next = after.into();
            guard = guard.saturating_add(1);
        }
        if len < 48 {
            len = 4096;
        }
        let span = file.sub(at, len);
        let id = source_id(&h);
        if !ids.contains(&id) && ids.len() < 16 {
            ids.push(id.clone());
        }
        samples = samples.saturating_add(h.samples.into());
        let rate = sample_rate(h.rate_factor, h.rate_multiplier);
        cx.push(
            Node::new(format!("Record {}", h.sequence.trim()))
                .span(span)
                .value(text(id))
                .summary(format!(
                    "{:04}-{:03} {:02}:{:02}:{:02}.{:04}, {} samples at {rate} Hz, {}",
                    h.year,
                    h.day,
                    h.hour,
                    h.minute,
                    h.second,
                    h.fraction,
                    h.samples,
                    encoding
                        .and_then(|e| lookup(MSEED_ENCODINGS, e.into()))
                        .unwrap_or("unknown encoding")
                ))
                .lazy(mseed2_record, (span, endian)),
        )
        .await;
        count = count.saturating_add(1);
        at = at.saturating_add(len);
    }
    cx.annotate(format!(
        "miniSEED, {count} record(s), {samples} samples, {}",
        ids.join(", ")
    ));
    Ok(())
}

async fn mseed2_record(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let h: MseedHeader = read_record(&cx, span.sub(0, MseedHeader::SIZE), endian).await?;
    cx.emit(MseedHeader::node(
        "Fixed header",
        span.sub(0, MseedHeader::SIZE),
        endian,
    ));
    let mut next = u64::from(h.first_blockette);
    let mut guard = 0u32;
    while next >= 48 && next < span.len && guard < 32 {
        let b = cx.block(span.sub(next, 8)).await?;
        let mut f = Fields::new(&b, endian);
        let kind = f.u16("Type").get()?;
        let after = f.u16("Next").get()?;
        let len = if after > 0 && u64::from(after) > next {
            u64::from(after).saturating_sub(next)
        } else if kind == 1000 || kind == 1001 {
            8
        } else {
            4
        };
        let bs = span.sub(next, len);
        let mut node = Node::new(format!("Blockette {kind}")).span(bs);
        if kind == 1000 {
            let enc = b.data.get(4).copied().unwrap_or(0);
            node = node
                .summary(format!(
                    "{}, {}, record length 2^{}",
                    lookup(MSEED_ENCODINGS, enc.into()).unwrap_or("?"),
                    if b.data.get(5) == Some(&1) {
                        "big endian"
                    } else {
                        "little endian"
                    },
                    b.data.get(6).copied().unwrap_or(0)
                ))
                .lazy(mseed_b1000, (bs, endian));
        } else if kind == 1001 {
            node = node.summary(format!(
                "timing quality {}%, µsec offset {}",
                b.data.get(4).copied().unwrap_or(0),
                b.data.get(5).copied().unwrap_or(0).cast_signed()
            ));
        }
        cx.emit(node);
        if after == 0 || u64::from(after) <= next {
            break;
        }
        next = after.into();
        guard = guard.saturating_add(1);
    }
    cx.emit(
        Node::new("Data")
            .span(span.tail(h.data_offset.into()))
            .summary(format!("{} sample(s)", h.samples)),
    );
    Ok(())
}

async fn mseed_b1000(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &b, endian);
    f.u16("Type").emit()?;
    f.u16("Next blockette").emit()?;
    f.u8("Encoding").enumeration(MSEED_ENCODINGS).emit()?;
    f.u8("Word order").emit()?;
    f.u8("Record length (log2)").emit()?;
    f.u8("Reserved").emit()?;
    Ok(())
}

record! {
    pub struct Mseed3Header {
        magic: ascii[2] "Record indicator",
        version: u8 "Format version",
        flags: u8 "Flags" .hex(),
        nanosecond: u32 "Nanosecond",
        year: u16 "Year",
        day: u16 "Day of year",
        hour: u8 "Hour",
        minute: u8 "Minute",
        second: u8 "Second",
        encoding: u8 "Encoding" .enumeration(MSEED_ENCODINGS),
        rate: f64 "Sample rate/period",
        samples: u32 "Number of samples",
        crc: u32 "CRC-32C" .hex(),
        publication: u8 "Publication version",
        sid_length: u8 "Source identifier length",
        extra_length: u16 "Extra headers length",
        data_length: u32 "Data length",
    }
}

async fn mseed3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let mut count = 0u64;
    let mut ids: Vec<String> = Vec::new();
    while at.saturating_add(Mseed3Header::SIZE) <= file.len {
        cx.progress_in(file, file.offset.saturating_add(at));
        let hs = file.sub(at, Mseed3Header::SIZE);
        let h: Mseed3Header = read_record(&cx, hs, LE).await?;
        if h.magic != "MS" {
            cx.diag(
                Diagnostic::malformed("expected a record indicator \"MS\"").at(file.sub(at, 2)),
            );
            break;
        }
        let sid_span = file.sub(at.saturating_add(Mseed3Header::SIZE), h.sid_length.into());
        let sid = String::from_utf8_lossy(&cx.read_avail(sid_span).await?).into_owned();
        let extra = file.sub(
            sid_span.end().saturating_sub(file.offset),
            h.extra_length.into(),
        );
        let data = file.sub(
            extra.end().saturating_sub(file.offset),
            h.data_length.into(),
        );
        let span = file.sub(
            at,
            data.end().saturating_sub(file.offset).saturating_sub(at),
        );
        if !ids.contains(&sid) && ids.len() < 16 {
            ids.push(sid.clone());
        }
        let rate = if h.rate < 0.0 { -1.0 / h.rate } else { h.rate };
        cx.push(
            Node::new(format!("Record {count}"))
                .span(span)
                .value(text(sid.clone()))
                .summary(format!(
                    "{:04}-{:03} {:02}:{:02}:{:02}.{:09}, {} samples at {rate} Hz",
                    h.year, h.day, h.hour, h.minute, h.second, h.nanosecond, h.samples
                ))
                .lazy(mseed3_record, (hs, sid_span, extra, data)),
        )
        .await;
        count = count.saturating_add(1);
        at = at.saturating_add(span.len.max(1));
    }
    cx.annotate(format!("miniSEED 3, {count} record(s), {}", ids.join(", ")));
    Ok(())
}

async fn mseed3_record(cx: Cx, (header, sid, extra, data): (Span, Span, Span, Span)) -> Result<()> {
    cx.emit(Mseed3Header::node("Fixed header", header, LE));
    let s = cx.read_avail(sid).await?;
    cx.emit(
        Node::new("Source identifier")
            .span(sid)
            .value(text(String::from_utf8_lossy(&s))),
    );
    if extra.len > 0 {
        let e = cx.read_avail(extra.sub(0, 4096)).await?;
        cx.emit(
            Node::new("Extra headers (JSON)")
                .span(extra)
                .value(text(preview(&String::from_utf8_lossy(&e), 200))),
        );
    }
    cx.emit(Node::new("Data").span(data));
    Ok(())
}

// ---------------------------------------------------------------------------
// SAC (Seismic Analysis Code)

fn sac_endian(h: &[u8]) -> Option<Endian> {
    let ok = |v: u32| v == 6 || v == 7;
    if u32_le(h, 304).is_some_and(ok) {
        Some(LE)
    } else if u32_be(h, 304).is_some_and(ok) {
        Some(BE)
    } else {
        None
    }
}

fn sac_probe(h: &Head<'_>) -> bool {
    let Some(endian) = sac_endian(h.data) else {
        return false;
    };
    let get = |o: usize| {
        if endian == LE {
            u32_le(h.data, o)
        } else {
            u32_be(h.data, o)
        }
    };
    let npts = get(280 + 9 * 4).unwrap_or(u32::MAX);
    let leven = get(280 + 35 * 4).unwrap_or(9);
    let delta = f32::from_bits(get(0).unwrap_or(0));
    (leven == 0 || leven == 1)
        && npts < 0x1000_0000
        && h.len >= 632u64.saturating_add(u64::from(npts).saturating_mul(4))
        && delta.is_finite()
}

declare_format!(pub SAC = "sac", "Seismic Analysis Code (SAC) waveform", ["sac"], "application/x-sac",
    Probe::Custom(sac_probe), sac);

const SAC_FLOATS: [&str; 70] = [
    "delta",
    "depmin",
    "depmax",
    "scale",
    "odelta",
    "b",
    "e",
    "o",
    "a",
    "internal1",
    "t0",
    "t1",
    "t2",
    "t3",
    "t4",
    "t5",
    "t6",
    "t7",
    "t8",
    "t9",
    "f",
    "resp0",
    "resp1",
    "resp2",
    "resp3",
    "resp4",
    "resp5",
    "resp6",
    "resp7",
    "resp8",
    "resp9",
    "stla",
    "stlo",
    "stel",
    "stdp",
    "evla",
    "evlo",
    "evel",
    "evdp",
    "mag",
    "user0",
    "user1",
    "user2",
    "user3",
    "user4",
    "user5",
    "user6",
    "user7",
    "user8",
    "user9",
    "dist",
    "az",
    "baz",
    "gcarc",
    "internal2",
    "internal3",
    "depmen",
    "cmpaz",
    "cmpinc",
    "xminimum",
    "xmaximum",
    "yminimum",
    "ymaximum",
    "unused1",
    "unused2",
    "unused3",
    "unused4",
    "unused5",
    "unused6",
    "unused7",
];
const SAC_INTS: [&str; 40] = [
    "nzyear",
    "nzjday",
    "nzhour",
    "nzmin",
    "nzsec",
    "nzmsec",
    "nvhdr",
    "norid",
    "nevid",
    "npts",
    "internal4",
    "nwfid",
    "nxsize",
    "nysize",
    "unused8",
    "iftype",
    "idep",
    "iztype",
    "unused9",
    "iinst",
    "istreg",
    "ievreg",
    "ievtyp",
    "iqual",
    "isynth",
    "imagtyp",
    "imagsrc",
    "unused10",
    "unused11",
    "unused12",
    "unused13",
    "unused14",
    "unused15",
    "unused16",
    "unused17",
    "leven",
    "lpspol",
    "lovrok",
    "lcalda",
    "unused18",
];
const SAC_STRINGS: [&str; 23] = [
    "kstnm", "kevnm", "khole", "ko", "ka", "kt0", "kt1", "kt2", "kt3", "kt4", "kt5", "kt6", "kt7",
    "kt8", "kt9", "kf", "kuser0", "kuser1", "kuser2", "kcmpnm", "knetwk", "kdatrd", "kinst",
];
const SAC_IFTYPE: EnumTable = &[
    (1, "ITIME (time series)"),
    (2, "IRLIM (spectral, real/imaginary)"),
    (3, "IAMPH (spectral, amplitude/phase)"),
    (4, "IXY (general x-y)"),
    (51, "IXYZ (general xyz)"),
];

async fn sac(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 632)).await?;
    let endian = sac_endian(&head).unwrap_or(LE);
    let geti = |i: usize| -> i32 {
        let o = 280usize.saturating_add(i.saturating_mul(4));
        if endian == LE {
            crate::bytes::i32_le(&head, o)
        } else {
            crate::bytes::i32_be(&head, o)
        }
        .unwrap_or(-12345)
    };
    let getf = |i: usize| -> f32 {
        let o = i.saturating_mul(4);
        f32::from_bits(
            if endian == LE {
                u32_le(&head, o)
            } else {
                u32_be(&head, o)
            }
            .unwrap_or(0),
        )
    };
    let gets = |i: usize| -> String {
        let (o, w) = if i == 0 {
            (440usize, 8usize)
        } else if i == 1 {
            (448, 16)
        } else {
            (
                464usize.saturating_add(i.saturating_sub(2).saturating_mul(8)),
                8,
            )
        };
        String::from_utf8_lossy(head.get(o..o.saturating_add(w)).unwrap_or_default())
            .trim_end_matches(['\0', ' '])
            .to_owned()
    };
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 632))
            .lazy(sac_header, (file.sub(0, 632), endian)),
    );
    let npts = u64::try_from(geti(9)).unwrap_or(0);
    let leven = geti(35);
    let iftype = geti(15);
    let components = if leven == 0 || matches!(iftype, 2 | 3) {
        2
    } else {
        1
    };
    let data = file.sub(632, npts.saturating_mul(4).saturating_mul(components));
    let sample = cx.read_avail(data.sub(0, 24)).await?;
    let shown: Vec<String> = sample
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| {
            f32::from_bits(if endian == LE {
                u32::from_le_bytes(*c)
            } else {
                u32::from_be_bytes(*c)
            })
            .to_string()
        })
        .collect();
    cx.emit(Node::new("Data").span(data).summary(format!(
        "{npts} float32 sample(s){}: {}",
        if components == 2 { " × 2" } else { "" },
        shown.join(", ")
    )));
    let id = [gets(20), gets(0), gets(2), gets(19)]
        .iter()
        .map(|s| {
            if s == "-12345" {
                String::new()
            } else {
                s.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(".");
    let delta = getf(0);
    cx.annotate(format!(
        "SAC v{} ({} endian), {id}, {npts} samples at {} Hz, start {:04}-{:03} {:02}:{:02}:{:02}.{:03}",
        geti(6),
        if endian == LE { "little" } else { "big" },
        if delta > 0.0 { (1.0 / f64::from(delta)).to_string() } else { "?".to_owned() },
        geti(0),
        geti(1),
        geti(2),
        geti(3),
        geti(4),
        geti(5)
    ));
    Ok(())
}

async fn sac_header(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let head = cx.read(span).await?;
    // Only defined values are shown; -12345 marks undefined fields.
    for (i, name) in SAC_FLOATS.iter().enumerate() {
        let o = i.saturating_mul(4);
        let v = f32::from_bits(
            if endian == LE {
                u32_le(&head, o)
            } else {
                u32_be(&head, o)
            }
            .unwrap_or(0),
        );
        if v != -12345.0 && !name.starts_with("internal") && !name.starts_with("unused") {
            cx.emit(
                Node::new(*name)
                    .span(span.sub(to_u64(o), 4))
                    .value(float32(v)),
            );
        }
    }
    for (i, name) in SAC_INTS.iter().enumerate() {
        let o = 280usize.saturating_add(i.saturating_mul(4));
        let v = if endian == LE {
            crate::bytes::i32_le(&head, o)
        } else {
            crate::bytes::i32_be(&head, o)
        }
        .unwrap_or(0);
        if v != -12345 && !name.starts_with("internal") && !name.starts_with("unused") {
            let value = if *name == "iftype" {
                enumeration(SAC_IFTYPE, u64::try_from(v).unwrap_or(0), 32)
            } else {
                int(v.into())
            };
            cx.emit(Node::new(*name).span(span.sub(to_u64(o), 4)).value(value));
        }
    }
    for (i, name) in SAC_STRINGS.iter().enumerate() {
        let (o, w) = if i == 0 {
            (440usize, 8usize)
        } else if i == 1 {
            (448, 16)
        } else {
            (
                464usize.saturating_add(i.saturating_sub(2).saturating_mul(8)),
                8,
            )
        };
        let s = String::from_utf8_lossy(head.get(o..o.saturating_add(w)).unwrap_or_default())
            .trim_end_matches(['\0', ' '])
            .to_owned();
        if s != "-12345" && !s.is_empty() {
            cx.emit(
                Node::new(*name)
                    .span(span.sub(to_u64(o), to_u64(w)))
                    .value(text(s)),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ERDAS IMAGINE (HFA)

declare_format!(pub ERDAS_IMG = "erdas-img", "ERDAS IMAGINE image (HFA)", ["img", "ige"], "application/x-erdas-hfa",
    Probe::Magic(&[(0, b"EHFA_HEADER_TAG\0")]), erdas);

record! {
    pub struct HfaFile {
        version: u32 "version",
        free_list: u32 "freeList" .hex(),
        root: u32 "rootEntryPtr" .hex(),
        entry_header_length: u16 "entryHeaderLength",
        dictionary: u32 "dictionaryPtr" .hex(),
    }
}

record! {
    pub struct HfaEntry {
        next: u32 "next" .hex(),
        prev: u32 "prev" .hex(),
        parent: u32 "parent" .hex(),
        child: u32 "child" .hex(),
        data: u32 "data" .hex(),
        data_size: u32 "dataSize",
        name: ascii[64] "name",
        kind: ascii[32] "type",
        mod_time: u32 "modTime" .timestamp(),
    }
}

async fn erdas(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 20)).await?;
    cx.emit(
        Node::new("Tag")
            .span(file.sub(0, 16))
            .value(text("EHFA_HEADER_TAG")),
    );
    let ptr = u64::from(u32_le(&head, 16).unwrap_or(0));
    cx.emit(
        Node::new("Header pointer")
            .span(file.sub(16, 4))
            .value(crate::formats::util::lines::hex(ptr, 32)),
    );
    let hs = file.sub(ptr, HfaFile::SIZE);
    let h: HfaFile = read_record(&cx, hs, LE).await?;
    cx.emit(HfaFile::node("File header", hs, LE));
    let (dict, dspan) = cx
        .cstr(file.sub(h.dictionary.into(), 0x10000))
        .await
        .unwrap_or_else(|_| (String::new(), file.sub(0, 0)));
    let types = dict.split(',').filter(|s| s.contains('{')).count();
    cx.emit(
        Node::new("Data dictionary")
            .span(dspan)
            .value(text(preview(&dict, 200)))
            .summary(format!("{types} type definition(s)")),
    );
    let root: HfaEntry = read_record(&cx, file.sub(h.root.into(), HfaEntry::SIZE), LE).await?;
    cx.emit(Node::new("Entries").lazy(hfa_children, (file, u64::from(h.root), Vec::<u64>::new())));
    // Layers are children of the root entry.
    let mut layers = Vec::new();
    let mut next = u64::from(root.child);
    let mut guard = 0u32;
    while next != 0 && guard < 1000 {
        let e: HfaEntry = read_record(&cx, file.sub(next, HfaEntry::SIZE), LE).await?;
        if e.kind.trim_end_matches('\0') == "Eimg_Layer" {
            layers.push(e.name.trim_end_matches('\0').to_owned());
        }
        next = e.next.into();
        guard = guard.saturating_add(1);
    }
    cx.annotate(format!(
        "ERDAS IMAGINE (HFA v{}), {} layer(s){}",
        h.version,
        layers.len(),
        if layers.is_empty() {
            String::new()
        } else {
            format!(": {}", preview(&layers.join(", "), 80))
        }
    ));
    Ok(())
}

/// Lists one entry and its children (as a lazy subtree), with cycle checks.
async fn hfa_children(cx: Cx, (file, at, path): (Span, u64, Vec<u64>)) -> Result<()> {
    if path.contains(&at) || path.len() > 32 {
        return Err(Diagnostic::malformed("entry tree loops or is too deep"));
    }
    let e: HfaEntry = read_record(&cx, file.sub(at, HfaEntry::SIZE), LE).await?;
    let mut node_path = path.clone();
    node_path.push(at);
    let name = e.name.trim_end_matches('\0').to_owned();
    let kind = e.kind.trim_end_matches('\0').to_owned();
    let mut node = HfaEntry::node(
        if name.is_empty() {
            "Root entry".to_owned()
        } else {
            format!("Entry {name}")
        },
        file.sub(at, HfaEntry::SIZE),
        LE,
    )
    .value(text(kind));
    if e.data != 0 {
        node = node
            .target(file.sub(e.data.into(), e.data_size.into()))
            .summary(format!("{} bytes of data", e.data_size));
    }
    cx.push(node).await;
    if e.child != 0 {
        let mut next = u64::from(e.child);
        let mut seen = Vec::new();
        while next != 0 && !seen.contains(&next) && seen.len() < 10_000 {
            seen.push(next);
            let c: HfaEntry = read_record(&cx, file.sub(next, HfaEntry::SIZE), LE).await?;
            let name = c.name.trim_end_matches('\0').to_owned();
            let kind = c.kind.trim_end_matches('\0').to_owned();
            cx.push(
                Node::new(format!("{name}/"))
                    .span(file.sub(next, HfaEntry::SIZE))
                    .value(text(kind))
                    .lazy(
                        crate::expander!(self::hfa_children: (Span, u64, Vec<u64>)),
                        (file, next, node_path.clone()),
                    ),
            )
            .await;
            next = c.next.into();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ASTM E57 point clouds

declare_format!(pub E57 = "e57", "ASTM E57 3D imaging data", ["e57"], "model/e57",
    Probe::Magic(&[(0, b"ASTM-E57")]), e57);

record! {
    pub struct E57Header {
        signature: ascii[8] "File signature",
        major: u32 "Major version",
        minor: u32 "Minor version",
        physical_length: u64 "Physical length",
        xml_offset: u64 "XML physical offset" .hex(),
        xml_length: u64 "XML logical length",
        page_size: u64 "Page size",
    }
}

async fn e57(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hs = file.sub(0, E57Header::SIZE);
    let h: E57Header = read_record(&cx, hs, LE).await?;
    cx.emit(E57Header::node("Header", hs, LE));
    let page = h.page_size;
    if !(64..=0x100_0000).contains(&page) {
        return Err(Diagnostic::malformed(format!("page size {page}")).at(hs));
    }
    let payload = page.saturating_sub(4);
    // Logical XML bytes are spread over pages, skipping each page's CRC.
    let mut pieces = Vec::new();
    let mut physical = h.xml_offset;
    let mut left = h.xml_length;
    while left > 0 && pieces.len() < 100_000 && physical < file.len {
        let in_page = physical.checked_rem(page).unwrap_or(0);
        let take = payload.saturating_sub(in_page).min(left);
        if take == 0 {
            physical = physical.saturating_add(page.saturating_sub(in_page));
            continue;
        }
        pieces.push(file.sub(physical, take));
        left = left.saturating_sub(take);
        physical = physical.saturating_add(take).saturating_add(4);
    }
    let xml = cx.add_pieces(
        Origin {
            parent: file,
            transform: "e57-pages",
        },
        pieces,
    )?;
    let head = cx.read_avail(xml.sub(0, 4096)).await?;
    let head = String::from_utf8_lossy(&head).into_owned();
    cx.emit(
        Node::new("XML section")
            .span(xml)
            .summary(format!("{} bytes", xml.len))
            .lazy(xml_lines, xml),
    );
    let pages = file.len.checked_div(page).unwrap_or(0);
    cx.emit(
        Node::new("Pages")
            .span(file)
            .value(uint(pages))
            .lazy(e57_pages, (file, page)),
    );
    let scans = head.matches("<vectorChild type=\"Structure\"").count();
    let guid = head
        .split_once("<guid")
        .and_then(|(_, r)| r.split_once("CDATA["))
        .and_then(|(_, r)| r.split_once("]]"))
        .map(|(g, _)| g.to_owned())
        .unwrap_or_default();
    cx.annotate(format!(
        "E57 {}.{}, {} page(s) of {page} bytes, XML {} bytes{}{}",
        h.major,
        h.minor,
        pages,
        h.xml_length,
        if scans > 0 {
            format!(", {scans} structure(s)")
        } else {
            String::new()
        },
        if guid.is_empty() {
            String::new()
        } else {
            format!(", {guid}")
        }
    ));
    Ok(())
}

async fn e57_pages(cx: Cx, (file, page): (Span, u64)) -> Result<()> {
    let count = file.len.checked_div(page).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = file.sub(i.saturating_mul(page), page);
        let data = cx.read(span).await?;
        let (body, crc) = data.split_at(data.len().saturating_sub(4));
        let stored = u32_be(crc, 0).unwrap_or(0);
        let computed = crc32c(body);
        let mut node = Node::new(format!("Page {i}"))
            .span(span)
            .value(crate::formats::util::lines::hex(stored.into(), 32));
        if stored != computed {
            node = node.diag(Diagnostic::warning(format!(
                "CRC-32C mismatch (computed {computed:#010x})"
            )));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The lines of an embedded text (XML) section.
async fn xml_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        cx.progress_in(span, span.offset.saturating_add(lines.pos()));
        let t = line.text();
        if !t.trim().is_empty() {
            cx.push(
                Node::new(format!("Line {}", line.pos))
                    .span(line.content())
                    .value(text(preview(&t, 200))),
            )
            .await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PCD (Point Cloud Library)

fn pcd_probe(h: &Head<'_>) -> bool {
    let lines = head_lines(h, 12);
    let first = lines.iter().find(|l| !l.starts_with(b"#"));
    (h.starts_with(b"# .PCD") || first.is_some_and(|l| l.starts_with(b"VERSION")))
        && lines.iter().any(|l| l.starts_with(b"FIELDS "))
}

declare_format!(pub PCD = "pcd", "Point Cloud Data (PCL)", ["pcd"], "application/x-pcd",
    Probe::Custom(pcd_probe), pcd);

#[derive(Clone, Debug)]
struct PcdField {
    name: String,
    size: u64,
    kind: char,
    count: u64,
}

fn pcd_value(b: &[u8], size: u64, kind: char) -> String {
    match (kind, size) {
        ('F', 4) => f32::from_bits(u32_le(b, 0).unwrap_or(0)).to_string(),
        ('F', 8) => f64::from_bits(crate::bytes::u64_le(b, 0).unwrap_or(0)).to_string(),
        ('I', 1) => b.first().copied().unwrap_or(0).cast_signed().to_string(),
        ('I', 2) => u16_le(b, 0).unwrap_or(0).cast_signed().to_string(),
        ('I', 4) => crate::bytes::i32_le(b, 0).unwrap_or(0).to_string(),
        ('U', 1) => b.first().copied().unwrap_or(0).to_string(),
        ('U', 2) => u16_le(b, 0).unwrap_or(0).to_string(),
        ('U', 4) => u32_le(b, 0).unwrap_or(0).to_string(),
        _ => format!("{b:02x?}"),
    }
}

async fn pcd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header: Vec<(String, String)> = Vec::new();
    let mut data_kind = String::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if t.starts_with('#') {
            cx.emit(
                Node::new("Comment")
                    .span(line.content())
                    .value(text(t.trim_start_matches('#').trim())),
            );
            continue;
        }
        let (k, v) = t.split_once(' ').unwrap_or((t.as_str(), ""));
        cx.emit(Node::new(k.to_owned()).span(line.content()).value(
            if matches!(k, "WIDTH" | "HEIGHT" | "POINTS") {
                number(v)
            } else {
                text(v.trim())
            },
        ));
        header.push((k.to_owned(), v.trim().to_owned()));
        if k == "DATA" {
            data_kind = v.trim().to_owned();
            break;
        }
        if header.len() > 64 {
            break;
        }
    }
    let get = |k: &str| {
        header
            .iter()
            .find(|(a, _)| a == k)
            .map_or("", |(_, v)| v.as_str())
    };
    let names: Vec<&str> = get("FIELDS").split_whitespace().collect();
    let sizes: Vec<u64> = get("SIZE")
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    let kinds: Vec<char> = get("TYPE")
        .split_whitespace()
        .filter_map(|s| s.chars().next())
        .collect();
    let counts: Vec<u64> = get("COUNT")
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    let fields: Vec<PcdField> = names
        .iter()
        .enumerate()
        .map(|(i, n)| PcdField {
            name: (*n).to_owned(),
            size: sizes.get(i).copied().unwrap_or(4),
            kind: kinds.get(i).copied().unwrap_or('F'),
            count: counts.get(i).copied().unwrap_or(1),
        })
        .collect();
    let points: u64 = get("POINTS").parse().unwrap_or(0);
    let data = file.tail(lines.pos());
    let mut node = Node::new("Data")
        .span(data)
        .summary(format!("{points} point(s), {data_kind}"));
    match data_kind.as_str() {
        "ascii" => {
            node = node.lazy(
                pcd_ascii,
                (
                    data,
                    names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                ),
            )
        }
        "binary" => node = node.lazy(pcd_binary, (data, fields.clone(), points)),
        "binary_compressed" => node = node.lazy(pcd_compressed, (input, data)),
        _ => {}
    }
    cx.emit(node);
    cx.annotate(format!(
        "PCD v{}, {points} point(s) ({}), {data_kind}",
        get("VERSION"),
        names.join(" ")
    ));
    Ok(())
}

async fn pcd_ascii(cx: Cx, (data, names): (Span, Vec<String>)) -> Result<()> {
    let mut lines = Lines::new(&cx, data);
    let mut i = 0u64;
    while let Some(line) = lines.next().await? {
        cx.progress_in(data, data.offset.saturating_add(lines.pos()));
        if line.bytes.is_empty() {
            continue;
        }
        let words = line.words();
        let shown: Vec<String> = names
            .iter()
            .zip(words.iter())
            .map(|(n, (w, _))| format!("{n}={w}"))
            .collect();
        cx.push(
            Node::new(format!("Point {i}"))
                .span(line.content())
                .value(text(shown.join(" "))),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// `binary_compressed`: compressed and uncompressed sizes, then LZF data
/// holding the fields one after another (each for all points).
async fn pcd_compressed(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    let head = cx.block(data.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, Endian::Little);
    let packed = f.u32("Compressed size").emit()?;
    let size = f.u32("Uncompressed size").emit()?;
    cx.emit(crate::formats::content(
        "Decompressed",
        input,
        data.sub(8, packed.into()),
        crate::codec::Codec::Lzf,
        Some(size.into()),
    ));
    Ok(())
}

async fn pcd_binary(cx: Cx, (data, fields, points): (Span, Vec<PcdField>, u64)) -> Result<()> {
    let size: u64 = fields.iter().map(|f| f.size.saturating_mul(f.count)).sum();
    if size == 0 {
        return Ok(());
    }
    let count = points.min(data.len.checked_div(size).unwrap_or(0));
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = data.sub(i.saturating_mul(size), size);
        let b = cx.read(span).await?;
        let mut at = 0usize;
        let mut shown = Vec::new();
        for f in &fields {
            let v = pcd_value(b.get(at..).unwrap_or_default(), f.size, f.kind);
            shown.push(format!("{}={v}", f.name));
            at = at.saturating_add(to_usize(f.size.saturating_mul(f.count)));
        }
        cx.push(
            Node::new(format!("Point {i}"))
                .span(span)
                .value(text(shown.join(" "))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LAS well logs (Canadian Well Logging Society)

fn las_log_probe(h: &Head<'_>) -> bool {
    is_text(h)
        && head_lines(h, 8)
            .iter()
            .find(|l| !l.starts_with(b"#") && !l.is_empty())
            .is_some_and(|l| l.starts_with(b"~V") || l.starts_with(b"~v"))
}

declare_format!(pub LAS_LOG = "las-log", "LAS well log (CWLS)", ["las"], "text/x-las-log",
    Probe::Custom(las_log_probe), las_log);

async fn las_log(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut section: Option<(String, u64, Vec<Line>)> = None;
    let (mut version, mut well, mut curves, mut rows) =
        (String::new(), String::new(), Vec::new(), 0u64);
    loop {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let next = lines.next().await?;
        let starts = next.as_ref().is_none_or(|l| l.bytes.starts_with(b"~"));
        if starts && let Some((name, start, body)) = section.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let span = file.sub(start, end.saturating_sub(start));
            let letter = name.chars().nth(1).unwrap_or(' ').to_ascii_uppercase();
            let n = body.len();
            let node = Node::new(name.clone()).span(span);
            if letter == 'A' {
                rows = to_u64(n);
                cx.push(
                    node.summary(format!("{n} row(s)"))
                        .lazy(las_rows, (body, curves.clone())),
                )
                .await;
            } else {
                for l in &body {
                    let (mnem, value, _) = las_line(&l.text());
                    match (letter, mnem.as_str()) {
                        ('V', "VERS") => version = value,
                        ('W', "WELL") => well = value,
                        ('C', _) if curves.len() < 4096 => curves.push(mnem),
                        _ => {}
                    }
                }
                cx.push(node.summary(format!("{n} line(s)")).lazy(las_section, body))
                    .await;
            }
        }
        let Some(line) = next else { break };
        if starts {
            section = Some((line.text().trim().to_owned(), line.pos, Vec::new()));
        } else if let Some((_, _, body)) = section.as_mut()
            && !line.bytes.is_empty()
            && !line.bytes.starts_with(b"#")
            && body.len() < 1_000_000
        {
            body.push(line);
        }
    }
    cx.annotate(format!(
        "LAS {version} well log{}, {} curve(s) ({}), {rows} row(s)",
        if well.is_empty() {
            String::new()
        } else {
            format!(" {well}")
        },
        curves.len(),
        preview(&curves.join(", "), 80)
    ));
    Ok(())
}

/// `MNEM.UNIT  DATA : DESCRIPTION` → (mnemonic, data, description).
fn las_line(t: &str) -> (String, String, String) {
    let (left, desc) = t.rsplit_once(':').unwrap_or((t, ""));
    let (mnem, rest) = left.split_once('.').unwrap_or((left, ""));
    // The unit runs to the first space after the dot.
    let data = rest.split_once(' ').map_or("", |(_, d)| d);
    (
        mnem.trim().to_owned(),
        data.trim().to_owned(),
        desc.trim().to_owned(),
    )
}

async fn las_section(cx: Cx, body: Vec<Line>) -> Result<()> {
    for l in body {
        let t = l.text();
        let (mnem, data, desc) = las_line(&t);
        let node = Node::new(mnem).span(l.content()).value(number(&data));
        cx.push(summarize(node, desc)).await;
    }
    Ok(())
}

async fn las_rows(cx: Cx, (body, curves): (Vec<Line>, Vec<String>)) -> Result<()> {
    for l in body {
        let words = l.words();
        let first = words.first().map_or(String::new(), |(w, _)| w.clone());
        let shown: Vec<String> = curves
            .iter()
            .zip(words.iter())
            .skip(1)
            .take(8)
            .map(|(c, (w, _))| format!("{c}={w}"))
            .collect();
        cx.push(
            Node::new(first)
                .span(l.content())
                .value(text(shown.join(" "))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Golden Software Surfer grids

declare_format!(pub SURFER_GRID = "surfer-grid", "Golden Software Surfer grid", ["grd"], "application/x-surfer-grid",
    Probe::Custom(|h| h.starts_with(b"DSAA") && h.data.get(4).is_some_and(|&b| b == b'\r' || b == b'\n') || h.starts_with(b"DSBB") || (h.starts_with(b"DSRB") && u32_le(h.data, 4) == Some(4))), surfer);

async fn surfer(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    match magic.as_slice() {
        b"DSAA" => {
            let mut lines = Lines::new(&cx, file);
            let names = ["ID", "nx ny", "xlo xhi", "ylo yhi", "zlo zhi"];
            let mut dims = String::new();
            for name in names {
                let Some(line) = lines.next().await? else {
                    break;
                };
                if name == "nx ny" {
                    dims = line.text().split_whitespace().collect::<Vec<_>>().join("×");
                }
                cx.emit(
                    Node::new(name)
                        .span(line.content())
                        .value(text(line.text().trim())),
                );
            }
            cx.emit(Node::new("Values").span(file.tail(lines.pos())));
            cx.annotate(format!("Surfer 6 ASCII grid, {dims} nodes"));
        }
        b"DSBB" => {
            let b = cx.block(file.sub(0, 56)).await?;
            let mut f = Fields::emitting(&cx, &b, LE);
            f.ascii("ID", 4).emit()?;
            let nx = f.u16("nx").emit()?;
            let ny = f.u16("ny").emit()?;
            for name in ["xlo", "xhi", "ylo", "yhi", "zlo", "zhi"] {
                f.f64(name).emit()?;
            }
            cx.emit(Node::new("Values").span(file.tail(56)).summary(format!(
                "{} float32 value(s)",
                u64::from(nx).saturating_mul(ny.into())
            )));
            cx.annotate(format!("Surfer 6 binary grid, {nx}×{ny} nodes"));
        }
        _ => {
            let mut cur = Cursor::new(&cx, file, LE);
            let mut dims = String::new();
            while cur.remaining() >= 8 {
                let start = cur.pos();
                let tag = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
                let size = cur.u32().await?;
                let body = cur.span(size.into());
                let mut node = Node::new(tag.clone())
                    .span(file.sub(start, 8u64.saturating_add(size.into())))
                    .summary(format!("{size} bytes"));
                if tag == "GRID" {
                    let b = cx.read_avail(body.sub(0, 8)).await?;
                    dims = format!(
                        "{}×{}",
                        u32_le(&b, 4).unwrap_or(0),
                        u32_le(&b, 0).unwrap_or(0)
                    );
                    node = node.lazy(surfer7_grid, body);
                }
                cx.push(node).await;
                cur.skip(size.into());
            }
            cx.annotate(format!(
                "Surfer 7 grid{}",
                if dims.is_empty() {
                    String::new()
                } else {
                    format!(", {dims} nodes")
                }
            ));
        }
    }
    Ok(())
}

async fn surfer7_grid(cx: Cx, span: Span) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &b, LE);
    f.u32("Rows").emit()?;
    f.u32("Columns").emit()?;
    for name in [
        "xLL",
        "yLL",
        "xSize",
        "ySize",
        "zMin",
        "zMax",
        "Rotation",
        "Blank value",
    ] {
        f.f64(name).emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ESRI ASCII grid

fn esri_grid_probe(h: &Head<'_>) -> bool {
    let lines = head_lines(h, 2);
    let starts = |l: Option<&&[u8]>, kw: &[u8]| {
        l.and_then(|l| l.get(..kw.len()))
            .is_some_and(|p| p.eq_ignore_ascii_case(kw))
    };
    is_text(h) && starts(lines.first(), b"ncols") && starts(lines.get(1), b"nrows")
}

declare_format!(pub ESRI_GRID = "esri-ascii-grid", "ESRI ASCII raster grid", ["asc", "grd"], "text/x-esri-ascii-grid",
    Probe::Custom(esri_grid_probe), esri_grid);

async fn esri_grid(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header: Vec<(String, String)> = Vec::new();
    let mut data_at = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let (k, v) = t
            .split_once(char::is_whitespace)
            .unwrap_or((t.as_str(), ""));
        if !k.chars().next().is_some_and(char::is_alphabetic) {
            data_at = line.pos;
            break;
        }
        cx.emit(
            Node::new(k.to_owned())
                .span(line.content())
                .value(number(v.trim())),
        );
        header.push((k.to_ascii_lowercase(), v.trim().to_owned()));
        data_at = lines.pos();
        if header.len() > 16 {
            break;
        }
    }
    let get = |k: &str| {
        header
            .iter()
            .find(|(a, _)| a == k)
            .map_or("?", |(_, v)| v.as_str())
    };
    let rows = file.tail(data_at);
    cx.emit(
        Node::new("Rows")
            .span(rows)
            .value(number(get("nrows")))
            .lazy(grid_rows, rows),
    );
    cx.annotate(format!(
        "ESRI ASCII grid, {}×{} cells of {}",
        get("ncols"),
        get("nrows"),
        get("cellsize")
    ));
    Ok(())
}

async fn grid_rows(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut i = 0u64;
    while let Some(line) = lines.next().await? {
        cx.progress_in(span, span.offset.saturating_add(lines.pos()));
        if line.bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let words = line.words();
        let shown: Vec<&str> = words.iter().take(10).map(|(w, _)| w.as_str()).collect();
        cx.push(
            Node::new(format!("Row {i}"))
                .span(line.content())
                .summary(format!(
                    "{} value(s): {}{}",
                    words.len(),
                    shown.join(" "),
                    if words.len() > 10 { " …" } else { "" }
                )),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ENVI header, PDS3 label, VICAR label (keyword = value text)

fn envi_probe(h: &Head<'_>) -> bool {
    head_lines(h, 1)
        .first()
        .is_some_and(|l| l.trim_ascii() == b"ENVI")
        && crate::formats::util::lines::contains(h.data.get(..4096).unwrap_or(h.data), b"samples")
}

declare_format!(pub ENVI_HDR = "envi-hdr", "ENVI raster header", ["hdr"], "text/x-envi-header",
    Probe::Custom(envi_probe), envi);

const ENVI_TYPES: EnumTable = &[
    (1, "uint8"),
    (2, "int16"),
    (3, "int32"),
    (4, "float32"),
    (5, "float64"),
    (6, "complex64"),
    (9, "complex128"),
    (12, "uint16"),
    (13, "uint32"),
    (14, "int64"),
    (15, "uint64"),
];

async fn envi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut current: Option<(String, String, u64)> = None;
    let mut pairs: Vec<(String, String)> = Vec::new();
    loop {
        let next = lines.next().await?;
        let complete = current
            .as_ref()
            .is_some_and(|(_, v, _)| !v.starts_with('{') || v.ends_with('}'));
        if (complete || next.is_none())
            && let Some((k, v, start)) = current.take()
        {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let span = file.sub(start, end.saturating_sub(start));
            let value = if k == "data type" {
                v.parse()
                    .map_or_else(|_| text(v.clone()), |t| enumeration(ENVI_TYPES, t, 8))
            } else {
                number(&v)
            };
            cx.push(Node::new(k.clone()).span(span).value(value)).await;
            pairs.push((k, v));
        }
        let Some(line) = next else { break };
        let t = line.text();
        if line.pos == 0 {
            cx.emit(
                Node::new("Signature")
                    .span(line.content())
                    .value(text(t.trim())),
            );
            continue;
        }
        if let Some((_, v, _)) = current.as_mut() {
            v.push(' ');
            v.push_str(t.trim());
        } else if let Some((k, v)) = t.split_once('=') {
            current = Some((k.trim().to_owned(), v.trim().to_owned(), line.pos));
        }
    }
    let get = |k: &str| {
        pairs
            .iter()
            .find(|(a, _)| a == k)
            .map_or("?", |(_, v)| v.as_str())
    };
    let dtype = get("data type")
        .parse()
        .ok()
        .and_then(|t| lookup(ENVI_TYPES, t))
        .unwrap_or("?");
    cx.annotate(format!(
        "ENVI header: {} samples × {} lines × {} bands, {dtype}, {}",
        get("samples"),
        get("lines"),
        get("bands"),
        get("interleave")
    ));
    Ok(())
}

fn pds_probe(h: &Head<'_>) -> bool {
    let first = h.data.get(..32).unwrap_or(h.data);
    (h.starts_with(b"PDS_VERSION_ID") || h.starts_with(b"ODL_VERSION_ID") || h.starts_with(b"PDS3"))
        && first.iter().all(|&b| b >= 0x20 || b == b'\r' || b == b'\n')
}

declare_format!(pub PDS3 = "pds", "NASA Planetary Data System label (PDS3/ODL)", ["lbl", "img", "pds"], "application/x-pds",
    Probe::Custom(pds_probe), pds3);

/// One ODL statement: keyword, value, span, and nested statements.
#[derive(Clone, Debug)]
struct OdlItem {
    key: String,
    value: String,
    span: Span,
    children: Vec<OdlItem>,
}

async fn pds3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    // Stack of open OBJECT/GROUP blocks.
    let mut stack: Vec<OdlItem> = vec![OdlItem {
        key: String::new(),
        value: String::new(),
        span: file,
        children: Vec::new(),
    }];
    let mut pending: Option<(String, String, u64, OdlBalance)> = None;
    let mut label_end = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.split("/*").next().unwrap_or_default().trim().to_owned();
        if let Some((k, v, start, balance)) = pending.as_mut() {
            v.push(' ');
            v.push_str(&t);
            // Counted per line: rescanning the whole value would make long
            // unbalanced values quadratic.
            balance.add(" ");
            balance.add(&t);
            if balance.complete() {
                let item = OdlItem {
                    key: std::mem::take(k),
                    value: std::mem::take(v),
                    span: file.sub(*start, lines.since(*start).len),
                    children: Vec::new(),
                };
                if let Some(top) = stack.last_mut() {
                    top.children.push(item);
                }
                pending = None;
            }
            continue;
        }
        if t == "END" {
            label_end = lines.pos();
            break;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim().to_owned(), v.trim().to_owned());
        match k.as_str() {
            "OBJECT" | "GROUP" if stack.len() < 32 => stack.push(OdlItem {
                key: format!("{k} {v}"),
                value: v,
                span: line.content(),
                children: Vec::new(),
            }),
            "END_OBJECT" | "END_GROUP" if stack.len() > 1 => {
                if let Some(mut done) = stack.pop() {
                    done.span = file.sub(
                        done.span.offset.saturating_sub(file.offset),
                        lines
                            .pos()
                            .saturating_sub(done.span.offset.saturating_sub(file.offset)),
                    );
                    if let Some(top) = stack.last_mut() {
                        top.children.push(done);
                    }
                }
            }
            _ if !odl_complete(&v) => {
                let mut balance = OdlBalance::new();
                balance.add(&v);
                pending = Some((k, v, line.pos, balance));
            }
            _ => {
                if let Some(top) = stack.last_mut()
                    && top.children.len() < 100_000
                {
                    top.children.push(OdlItem {
                        key: k,
                        value: v,
                        span: line.content(),
                        children: Vec::new(),
                    });
                }
            }
        }
    }
    while stack.len() > 1 {
        if let Some(done) = stack.pop()
            && let Some(top) = stack.last_mut()
        {
            top.children.push(done);
        }
    }
    let root = stack.pop().map(|r| r.children).unwrap_or_default();
    let get = |k: &str| {
        root.iter()
            .find(|i| i.key == k)
            .map(|i| i.value.trim_matches('"').to_owned())
            .unwrap_or_default()
    };
    let record_bytes: u64 = get("RECORD_BYTES").parse().unwrap_or(0);
    let objects: Vec<String> = root
        .iter()
        .filter(|i| i.key.starts_with("OBJECT "))
        .map(|i| i.value.clone())
        .collect();
    let pointers: Vec<(String, u64)> = root
        .iter()
        .filter(|i| i.key.starts_with('^'))
        .filter_map(|i| {
            i.value.trim().parse::<u64>().ok().map(|r| {
                (
                    i.key.clone(),
                    r.saturating_sub(1).saturating_mul(record_bytes),
                )
            })
        })
        .collect();
    cx.emit(
        Node::new("Label")
            .span(file.sub(0, label_end))
            .value(uint(to_u64(root.len())))
            .lazy(odl_items, root.clone()),
    );
    for (k, offset) in &pointers {
        cx.emit(
            Node::new(format!("{} data", k.trim_start_matches('^')))
                .span(file.tail(*offset))
                .desc("Pointed to by the label"),
        );
    }
    cx.annotate(format!(
        "{} label{}{}{}",
        get("PDS_VERSION_ID"),
        if get("INSTRUMENT_ID").is_empty() {
            String::new()
        } else {
            format!(", {}", get("INSTRUMENT_ID"))
        },
        if get("PRODUCT_ID").is_empty() {
            String::new()
        } else {
            format!(" {}", get("PRODUCT_ID"))
        },
        if objects.is_empty() {
            String::new()
        } else {
            format!(", object(s): {}", objects.join(", "))
        }
    ));
    Ok(())
}

/// Counts of a value's quotes, parentheses and braces, added to as the
/// value grows.
struct OdlBalance {
    quotes: usize,
    open: usize,
    close: usize,
    empty: bool,
}

impl OdlBalance {
    fn new() -> Self {
        OdlBalance {
            quotes: 0,
            open: 0,
            close: 0,
            empty: true,
        }
    }

    fn add(&mut self, s: &str) {
        self.quotes = self.quotes.saturating_add(s.matches('"').count());
        self.open = self.open.saturating_add(s.matches(['(', '{']).count());
        self.close = self.close.saturating_add(s.matches([')', '}']).count());
        self.empty = self.empty && s.is_empty();
    }

    /// Whether the quotes, parentheses and braces are balanced.
    fn complete(&self) -> bool {
        self.quotes.is_multiple_of(2) && self.close >= self.open && !self.empty
    }
}

/// Whether a value's quotes, parentheses and braces are balanced.
fn odl_complete(v: &str) -> bool {
    let mut b = OdlBalance::new();
    b.add(v);
    b.complete()
}

async fn odl_items(cx: Cx, items: Vec<OdlItem>) -> Result<()> {
    for item in items {
        let node = Node::new(item.key.clone()).span(item.span);
        if item.children.is_empty() {
            cx.push(node.value(number(item.value.trim_matches('"'))))
                .await;
        } else {
            let n = item.children.len();
            cx.push(node.summary(format!("{n} item(s)")).lazy(
                crate::expander!(self::odl_items: Vec<OdlItem>),
                item.children,
            ))
            .await;
        }
    }
    Ok(())
}

declare_format!(pub VICAR = "vicar", "VICAR image", ["vic", "img", "vicar"], "image/x-vicar",
    Probe::Custom(|h| h.starts_with(b"LBLSIZE=") && h.data.get(8..20).is_some_and(|d| d.first().is_some_and(u8::is_ascii_digit))), vicar);

/// Splits a VICAR label into `key=value` items with byte offsets.
fn vicar_items(label: &str) -> Vec<(String, String, usize, usize)> {
    let b = label.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() && out.len() < 10_000 {
        while b.get(i).is_some_and(|c| *c == b' ' || *c == 0) {
            i = i.saturating_add(1);
        }
        let start = i;
        while b
            .get(i)
            .is_some_and(|c| *c != b'=' && *c != b' ' && *c != 0)
        {
            i = i.saturating_add(1);
        }
        let key = label.get(start..i).unwrap_or_default().to_owned();
        if b.get(i) != Some(&b'=') {
            if key.is_empty() {
                break;
            }
            continue;
        }
        i = i.saturating_add(1);
        let vstart = i;
        let mut quote = false;
        let mut depth = 0u32;
        while let Some(&c) = b.get(i) {
            match c {
                b'\'' => quote = !quote,
                b'(' if !quote => depth = depth.saturating_add(1),
                b')' if !quote => depth = depth.saturating_sub(1),
                b' ' | 0 if !quote && depth == 0 => break,
                _ => {}
            }
            i = i.saturating_add(1);
        }
        let value = label
            .get(vstart..i)
            .unwrap_or_default()
            .trim_matches('\'')
            .to_owned();
        out.push((key, value, start, i));
    }
    out
}

async fn vicar(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 64)).await?;
    let size: u64 = String::from_utf8_lossy(head.get(8..).unwrap_or_default())
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let label_span = file.sub(0, size);
    let label =
        String::from_utf8_lossy(&cx.read_avail(label_span.sub(0, 0x100000)).await?).into_owned();
    let items = vicar_items(&label);
    let get = |k: &str| {
        items
            .iter()
            .find(|(a, ..)| a == k)
            .map_or(String::new(), |(_, v, ..)| v.clone())
    };
    let tasks = items.iter().filter(|(k, ..)| k == "TASK").count();
    let n = items.len();
    cx.emit(
        Node::new("Label")
            .span(label_span)
            .summary(format!("{n} item(s), {tasks} history task(s)"))
            .lazy(vicar_label, (label_span, items.clone())),
    );
    let recsize: u64 = get("RECSIZE").parse().unwrap_or(0);
    let nlb: u64 = get("NLB").parse().unwrap_or(0);
    let image_at = size.saturating_add(nlb.saturating_mul(recsize));
    if nlb > 0 {
        cx.emit(Node::new("Binary header").span(file.sub(size, nlb.saturating_mul(recsize))));
    }
    cx.emit(Node::new("Image").span(file.tail(image_at)));
    cx.annotate(format!(
        "VICAR image {}×{}×{} (NS×NL×NB), {} {}",
        get("NS"),
        get("NL"),
        get("NB"),
        get("FORMAT"),
        get("ORG")
    ));
    Ok(())
}

async fn vicar_label(
    cx: Cx,
    (span, items): (Span, Vec<(String, String, usize, usize)>),
) -> Result<()> {
    for (k, v, s, e) in items {
        cx.push(
            Node::new(k)
                .span(span.sub(to_u64(s), to_u64(e.saturating_sub(s))))
                .value(number(&v)),
        )
        .await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ibm_floats() {
        assert!((ibm_float(0x4110_0000) - 1.0).abs() < 1e-12);
        assert!((ibm_float(0xc276_a000) + 118.625).abs() < 1e-9);
        assert_eq!(ibm_float(0), 0.0);
    }

    #[test]
    fn crc32c_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn helpers() {
        assert_eq!(ebcdic(b"\xc3\x40\xf1"), "C 1");
        assert_eq!(sample_rate(100, 1), 100.0);
        assert_eq!(sample_rate(-10, 1), 0.1);
        assert_eq!(
            las_line("STRT.M        1670.0000 : START DEPTH"),
            (
                "STRT".to_owned(),
                "1670.0000".to_owned(),
                "START DEPTH".to_owned()
            )
        );
        let items = vicar_items("LBLSIZE=100 FORMAT='BYTE' DIM=3 ITEM=(1,2) TASK='X Y'");
        assert_eq!(
            items.iter().map(|i| i.0.as_str()).collect::<Vec<_>>(),
            vec!["LBLSIZE", "FORMAT", "DIM", "ITEM", "TASK"]
        );
        assert!(odl_complete("(1, 2)") && !odl_complete("(1,") && !odl_complete("\"abc"));
        let _ = uint(0);
    }
}
