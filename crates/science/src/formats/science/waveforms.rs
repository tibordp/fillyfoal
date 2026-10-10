//! Recorded signals and waveforms: CED Spike2 data files, Axon text files,
//! Igor text and LabVIEW measurement files, oscilloscope waveforms (Keysight,
//! Tektronix, LeCroy) and GTKWave FST traces.

use super::kv_spans;
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{
    Lines, contains, head_lines, is_text, preview, summarize, text, uint,
};
use crate::formats::{Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// CED Spike2 (SON) data files

declare_format!(pub SPIKE2 = "spike2-smr", "CED Spike2 data file (SON)", ["smr", "srf"], "application/x-spike2",
    Probe::Magic(&[(2, b"(C) CED 87")]), spike2);

const SON_KINDS: EnumTable = &[
    (0, "off"),
    (1, "waveform (ADC)"),
    (2, "event (falling)"),
    (3, "event (rising)"),
    (4, "event (both)"),
    (5, "marker"),
    (6, "ADC marker"),
    (7, "real marker"),
    (8, "text marker"),
    (9, "real wave"),
];

async fn spike2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 512)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let version = f.u16("System ID").emit()?;
    f.ascii("Copyright", 10).emit()?;
    f.ascii("Creator", 8).emit()?;
    let us = f.u16("µs per time unit").emit()?;
    f.u16("Time units per ADC").emit()?;
    f.u16("File state").emit()?;
    f.u32("First data block").hex().emit()?;
    let channels = f.u16("Channels").emit()?;
    f.u16("Channel header size").emit()?;
    f.u16("Extra data").emit()?;
    f.u16("Buffer size").emit()?;
    f.u16("OS format").emit()?;
    let max = f.u32("Maximum time").emit()?;
    let base = f.f64("Time base (s)").emit()?;
    f.bytes("Date/time", 8).emit()?;
    f.skip(52);
    let mut comments = Vec::new();
    for _ in 0..5 {
        let span = f.peek_span(80);
        let b = f.bytes("Comment", 80).get()?;
        let n = usize::from(b.first().copied().unwrap_or(0)).min(79);
        let c =
            String::from_utf8_lossy(b.get(1..n.saturating_add(1)).unwrap_or_default()).into_owned();
        if !c.is_empty() {
            cx.emit(Node::new("Comment").span(span).value(text(c.clone())));
            comments.push(c);
        }
    }
    let chans = file.sub(512, u64::from(channels).saturating_mul(140));
    cx.emit(
        Node::new("Channels")
            .span(chans)
            .value(uint(channels.into()))
            .lazy(son_channels, chans),
    );
    cx.emit(Node::new("Data blocks").span(file.tail(chans.end().saturating_sub(file.offset))));
    let seconds = f64::from(max) * f64::from(us) * if base > 0.0 { base } else { 1e-6 };
    cx.annotate(format!(
        "Spike2 v{version}, {channels} channel slot(s), {seconds:.3} s{}",
        comments
            .first()
            .map(|c| format!(", {c}"))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn son_channels(cx: Cx, span: Span) -> Result<()> {
    let mut at = 0u64;
    let mut i = 0u32;
    while at.saturating_add(140) <= span.len {
        let s = span.sub(at, 140);
        let b = cx.read(s).await?;
        let kind = b.get(122).copied().unwrap_or(0);
        let pstr = |o: usize, max: usize| {
            let n = usize::from(b.get(o).copied().unwrap_or(0)).min(max);
            String::from_utf8_lossy(
                b.get(o.saturating_add(1)..o.saturating_add(1).saturating_add(n))
                    .unwrap_or_default(),
            )
            .into_owned()
        };
        let title = pstr(108, 9);
        let comment = pstr(26, 71);
        let rate = f32::from_le_bytes(crate::bytes::array(&b, 118).unwrap_or_default());
        let blocks = u16_le(&b, 14).unwrap_or(0);
        if kind != 0 {
            let node = Node::new(format!("{i}: {title}")).span(s).value(
                crate::formats::util::lines::enumeration(SON_KINDS, kind.into(), 8),
            );
            cx.push(summarize(
                node,
                format!(
                    "{blocks} block(s), ideal rate {rate} Hz{}",
                    if comment.is_empty() {
                        String::new()
                    } else {
                        format!(", {comment}")
                    }
                ),
            ))
            .await;
        }
        at = at.saturating_add(140);
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Axon text files, Igor text, LabVIEW measurement files

declare_format!(pub AXON_ATF = "axon-atf", "Axon Text File (ATF)", ["atf"], "text/x-axon-atf",
    Probe::Custom(|h| h.starts_with(b"ATF\t") || h.starts_with(b"ATF ")), axon_atf);

async fn axon_atf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header_lines = 0usize;
    let mut columns = 0usize;
    let mut index = 0usize;
    let mut items = Vec::new();
    let mut titles = String::new();
    let mut rows = 0u64;
    let mut data_start = None;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        match index {
            0 => cx.emit(
                Node::new("Version")
                    .span(line.content())
                    .value(text(t.trim())),
            ),
            1 => {
                let w: Vec<usize> = t
                    .split_whitespace()
                    .filter_map(|x| x.parse().ok())
                    .collect();
                header_lines = w.first().copied().unwrap_or(0);
                columns = w.get(1).copied().unwrap_or(0);
                cx.emit(
                    Node::new("Header records / columns")
                        .span(line.content())
                        .value(text(t.trim())),
                );
            }
            _ if index < header_lines.saturating_add(2) => {
                let body = t.trim().trim_matches('"');
                let (k, v) = body.split_once('=').unwrap_or((body, ""));
                items.push((k.to_owned(), v.to_owned(), line.content()));
            }
            _ if index == header_lines.saturating_add(2) => {
                titles = t
                    .split('\t')
                    .map(|c| c.trim().trim_matches('"'))
                    .collect::<Vec<_>>()
                    .join(", ");
                cx.emit(
                    Node::new("Column titles")
                        .span(line.content())
                        .value(text(titles.clone())),
                );
                data_start = Some(lines.pos());
            }
            _ => {
                if !t.trim().is_empty() {
                    rows = rows.saturating_add(1);
                }
            }
        }
        index = index.saturating_add(1);
    }
    let n = items.len();
    cx.emit(
        Node::new("Header records")
            .value(uint(to_u64(n)))
            .lazy(kv_spans, items),
    );
    if let Some(at) = data_start {
        cx.emit(
            Node::new("Data")
                .span(file.tail(at))
                .value(uint(rows))
                .summary(format!("{columns} column(s)")),
        );
    }
    cx.annotate(format!(
        "Axon ATF, {columns} column(s) ({}), {rows} row(s)",
        preview(&titles, 80)
    ));
    Ok(())
}

declare_format!(pub IGOR_ITX = "igor-itx", "Igor Pro text wave file", ["itx", "awav"], "text/x-igor-itx",
    Probe::Custom(|h| head_lines(h, 1).first().is_some_and(|l| l.trim_ascii() == b"IGOR") && is_text(h)), igor_itx);

async fn igor_itx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut block: Option<(String, u64, u64)> = None;
    let mut waves = Vec::new();
    let mut commands = 0u64;
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let t = line.text();
        let t = t.trim();
        if let Some((decl, start, n)) = block.as_mut() {
            if t == "END" {
                let s = file.sub(*start, lines.pos().saturating_sub(*start));
                cx.push(
                    Node::new(decl.clone())
                        .span(s)
                        .value(uint(*n))
                        .desc("Data rows"),
                )
                .await;
                block = None;
            } else if t != "BEGIN" {
                *n = n.saturating_add(1);
            }
            continue;
        }
        if t.starts_with("WAVES") {
            let names = t
                .split_once(char::is_whitespace)
                .map_or("", |(_, r)| r)
                .trim();
            waves.push(names.to_owned());
            block = Some((t.to_owned(), line.pos, 0));
        } else if let Some(cmd) = t.strip_prefix("X ") {
            commands = commands.saturating_add(1);
            cx.push(Node::new("Command").span(line.content()).value(text(cmd)))
                .await;
        }
    }
    cx.annotate(format!(
        "Igor Pro text, wave(s) {}, {commands} command(s)",
        preview(&waves.join("; "), 100)
    ));
    Ok(())
}

declare_format!(pub LABVIEW_LVM = "labview-lvm", "LabVIEW measurement file (LVM)", ["lvm"], "text/x-labview-lvm",
    Probe::Custom(|h| h.starts_with(b"LabVIEW Measurement")), labview_lvm);

async fn labview_lvm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut items = Vec::new();
    let mut segments = 0u32;
    let mut channels = String::new();
    let mut in_header = true;
    let mut seg_start = None;
    let mut rows = 0u64;
    loop {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let next = lines.next().await?;
        let ends = next
            .as_ref()
            .is_none_or(|l| l.text().starts_with("***End_of_Header***"));
        if ends && let Some(start) = seg_start.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            cx.push(
                Node::new(format!("Segment {segments}"))
                    .span(file.sub(start, end.saturating_sub(start)))
                    .value(uint(rows)),
            )
            .await;
            segments = segments.saturating_add(1);
            rows = 0;
        }
        let Some(line) = next else { break };
        let t = line.text();
        if t.starts_with("***End_of_Header***") {
            if in_header {
                in_header = false;
                cx.emit(
                    Node::new("File header")
                        .value(uint(to_u64(items.len())))
                        .lazy(kv_spans, std::mem::take(&mut items)),
                );
            } else {
                seg_start = Some(lines.pos());
            }
            continue;
        }
        let fields: Vec<&str> = t.split('\t').collect();
        if in_header {
            if let (Some(k), Some(v)) = (fields.first(), fields.get(1)) {
                items.push(((*k).to_owned(), (*v).to_owned(), line.content()));
            }
        } else if seg_start.is_some() {
            if fields.first() == Some(&"X_Value") && channels.is_empty() {
                channels = fields
                    .iter()
                    .skip(1)
                    .filter(|f| !f.is_empty() && **f != "Comment")
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ");
            } else if fields.first().is_some_and(|f| f.parse::<f64>().is_ok()) {
                rows = rows.saturating_add(1);
            }
        } else {
            seg_start = Some(line.pos);
        }
    }
    cx.annotate(format!(
        "LabVIEW measurement file, {segments} segment(s), channel(s) {}",
        preview(&channels, 80)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Oscilloscope waveforms: Keysight/Agilent .bin, Tektronix .isf, LeCroy .trc

declare_format!(pub KEYSIGHT_BIN = "keysight-bin", "Keysight/Agilent oscilloscope waveform (.bin)", ["bin"], "application/x-keysight-bin",
    Probe::Custom(|h| (h.at(0, b"AG10") || h.at(0, b"AG01") || h.at(0, b"AG03")) && u32_le(h.data, 4).is_some_and(|s| u64::from(s) == h.len) && u32_le(h.data, 12) == Some(140)), keysight_bin);

const KS_WAVEFORMS: EnumTable = &[
    (0, "unknown"),
    (1, "normal"),
    (2, "peak detect"),
    (3, "average"),
    (4, "horizontal histogram"),
    (5, "vertical histogram"),
    (6, "logic"),
];
const KS_UNITS: EnumTable = &[
    (0, "unknown"),
    (1, "volts"),
    (2, "seconds"),
    (3, "constant"),
    (4, "amps"),
    (5, "decibels"),
    (6, "hertz"),
];

record! {
    pub struct KsWaveform {
        header_size: u32 "Header size",
        kind: u32 "Waveform type" .enumeration(KS_WAVEFORMS),
        buffers: u32 "Buffers",
        points: u32 "Points",
        count: u32 "Count",
        x_range: f32 "X display range",
        x_display_origin: f64 "X display origin",
        x_increment: f64 "X increment",
        x_origin: f64 "X origin",
        x_units: u32 "X units" .enumeration(KS_UNITS),
        y_units: u32 "Y units" .enumeration(KS_UNITS),
        date: ascii[16] "Date",
        time: ascii[16] "Time",
        frame: ascii[24] "Frame",
        label: ascii[16] "Label",
        time_tag: f64 "Time tag",
        segment: u32 "Segment index",
    }
}

async fn keysight_bin(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let cookie = f.ascii("Cookie and version", 4).emit()?;
    f.u32("File size").emit()?;
    let waveforms = f.u32("Waveforms").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    let mut labels = Vec::new();
    for _ in 0..waveforms.min(64) {
        let start = cur.pos();
        let size = u64::from(cur.u32().await?);
        cur.seek(start);
        let w: KsWaveform = read_record(&cx, file.sub(start, KsWaveform::SIZE), LE).await?;
        cur.skip(size.max(4));
        let mut buffers = Vec::new();
        for _ in 0..w.buffers.min(16) {
            let bstart = cur.pos();
            let hsize = u64::from(cur.u32().await?);
            let btype = cur.u16().await?;
            let bpp = cur.u16().await?;
            let bsize = u64::from(cur.u32().await?);
            cur.seek(bstart.saturating_add(hsize.max(12)));
            buffers.push((file.sub(bstart, hsize.max(12)), cur.span(bsize), btype, bpp));
            cur.skip(bsize);
        }
        let label = w.label.trim_end_matches('\0').to_owned();
        labels.push(label.clone());
        cx.push(
            KsWaveform::node(
                format!("Waveform {label}"),
                file.sub(start, KsWaveform::SIZE),
                LE,
            )
            .summary(format!(
                "{} points, Δx {} s, {} {}",
                w.points,
                w.x_increment,
                w.date.trim_end_matches('\0'),
                w.time.trim_end_matches('\0')
            ))
            .target(file.sub(start, cur.pos().saturating_sub(start))),
        )
        .await;
        for (h, data, btype, bpp) in buffers {
            cx.push(
                Node::new(format!("Buffer of waveform {label}"))
                    .span(data)
                    .summary(format!("type {btype}, {bpp} byte(s)/point"))
                    .target(h),
            )
            .await;
        }
    }
    cx.annotate(format!(
        "Keysight waveform file {cookie}, {waveforms} waveform(s): {}",
        labels.join(", ")
    ));
    Ok(())
}

declare_format!(pub TEKTRONIX_ISF = "tektronix-isf", "Tektronix internal save file (ISF)", ["isf"], "application/x-tektronix-isf",
    Probe::Custom(|h| (h.starts_with(b":WFMPRE:") || h.starts_with(b":WFMP:") || h.starts_with(b":WFMOUTPRE:")) && contains(h.data.get(..4096).unwrap_or(h.data), b"CURVE")), tektronix_isf);

async fn tektronix_isf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x4000)).await?;
    let curve = head
        .windows(7)
        .position(|w| w == b":CURVE ")
        .or_else(|| crate::bytes::find(&head, b"CURVE ", 0))
        .ok_or_else(|| Diagnostic::malformed("no CURVE block"))?;
    let text_part = String::from_utf8_lossy(head.get(..curve).unwrap_or_default()).into_owned();
    let mut items = Vec::new();
    let mut at = 0u64;
    for part in text_part.split(';') {
        let len = to_u64(part.len());
        let body = part.trim().rsplit(':').next().unwrap_or_default();
        let (k, v) = body.split_once(char::is_whitespace).unwrap_or((body, ""));
        if !k.is_empty() {
            items.push((
                k.to_owned(),
                v.trim().trim_matches('"').to_owned(),
                file.sub(at, len),
            ));
        }
        at = at.saturating_add(len).saturating_add(1);
    }
    let get = |key: &str| {
        items
            .iter()
            .find(|(a, _, _)| a.eq_ignore_ascii_case(key))
            .map_or(String::new(), |(_, v, _)| v.clone())
    };
    let n = items.len();
    cx.emit(
        Node::new("Preamble")
            .span(file.sub(0, to_u64(curve)))
            .value(uint(to_u64(n)))
            .lazy(kv_spans, items.clone()),
    );
    // IEEE 488.2 definite-length block: '#', digit count, length digits.
    let hash = head
        .get(curve..)
        .and_then(|r| r.iter().position(|&b| b == b'#'))
        .map(|p| curve.saturating_add(p));
    if let Some(h) = hash {
        let digits = usize::from(
            head.get(h.saturating_add(1))
                .copied()
                .unwrap_or(b'0')
                .saturating_sub(b'0'),
        );
        let len: u64 = String::from_utf8_lossy(
            head.get(h.saturating_add(2)..h.saturating_add(2).saturating_add(digits))
                .unwrap_or_default(),
        )
        .parse()
        .unwrap_or(0);
        let data_at = to_u64(h.saturating_add(2).saturating_add(digits));
        cx.emit(
            Node::new("Curve block header")
                .span(file.sub(to_u64(h), data_at.saturating_sub(to_u64(h))))
                .value(uint(len)),
        );
        cx.emit(
            Node::new("Curve data")
                .span(file.sub(data_at, len))
                .summary(format!("{} {}-byte point(s)", get("NR_PT"), get("BYT_NR"))),
        );
    }
    cx.annotate(format!(
        "Tektronix ISF, {} point(s), {}, Δx {} {}",
        get("NR_PT"),
        preview(&get("WFID"), 60),
        get("XINCR"),
        get("XUNIT")
    ));
    Ok(())
}

declare_format!(pub LECROY_TRC = "lecroy-trc", "Teledyne LeCroy waveform (.trc)", ["trc"], "application/x-lecroy-trc",
    Probe::Custom(|h| (h.at(0, b"WAVEDESC") && h.at(16, b"LECROY_")) || (h.at(11, b"WAVEDESC") && h.at(27, b"LECROY_"))), lecroy_trc);

async fn lecroy_trc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let start: u64 = if cx.read(file.sub(0, 8)).await? == b"WAVEDESC" {
        0
    } else {
        11
    };
    if start > 0 {
        cx.emit(Node::new("Block header").span(file.sub(0, 11)).value(text(
            String::from_utf8_lossy(&cx.read(file.sub(0, 11)).await?).into_owned(),
        )));
    }
    let d = file.sub(start, 346);
    let raw = cx.read(d).await?;
    let little = u16_le(&raw, 34) == Some(1);
    let endian = if little { LE } else { BE };
    let b = cx.block(d).await?;
    let mut f = Fields::emitting(&cx, &b, endian);
    f.ascii("DESCRIPTOR_NAME", 16).emit()?;
    let template = f.ascii("TEMPLATE_NAME", 16).emit()?;
    let comm_type = f.u16("COMM_TYPE").desc("0 = byte, 1 = word").emit()?;
    f.u16("COMM_ORDER")
        .desc("0 = big endian, 1 = little endian")
        .emit()?;
    let desc_len = f.u32("WAVE_DESCRIPTOR").emit()?;
    let user = f.u32("USER_TEXT").emit()?;
    f.u32("RES_DESC1").emit()?;
    let trig = f.u32("TRIGTIME_ARRAY").emit()?;
    let ris = f.u32("RIS_TIME_ARRAY").emit()?;
    f.u32("RES_ARRAY1").emit()?;
    let wave1 = f.u32("WAVE_ARRAY_1").emit()?;
    let wave2 = f.u32("WAVE_ARRAY_2").emit()?;
    f.u32("RES_ARRAY2").emit()?;
    f.u32("RES_ARRAY3").emit()?;
    let instrument = f.ascii("INSTRUMENT_NAME", 16).emit()?;
    f.u32("INSTRUMENT_NUMBER").emit()?;
    let label = f.ascii("TRACE_LABEL", 16).emit()?;
    f.u16("RESERVED1").emit()?;
    f.u16("RESERVED2").emit()?;
    let count = f.u32("WAVE_ARRAY_COUNT").emit()?;
    for n in [
        "PNTS_PER_SCREEN",
        "FIRST_VALID_PNT",
        "LAST_VALID_PNT",
        "FIRST_POINT",
        "SPARSING_FACTOR",
        "SEGMENT_INDEX",
        "SUBARRAY_COUNT",
        "SWEEPS_PER_ACQ",
    ] {
        f.u32(n).emit()?;
    }
    f.u16("POINTS_PER_PAIR").emit()?;
    f.u16("PAIR_OFFSET").emit()?;
    let gain = f.f32("VERTICAL_GAIN").emit()?;
    f.f32("VERTICAL_OFFSET").emit()?;
    f.f32("MAX_VALUE").emit()?;
    f.f32("MIN_VALUE").emit()?;
    f.u16("NOMINAL_BITS").emit()?;
    f.u16("NOM_SUBARRAY_COUNT").emit()?;
    let interval = f.f32("HORIZ_INTERVAL").emit()?;
    f.f64("HORIZ_OFFSET").emit()?;
    f.f64("PIXEL_OFFSET").emit()?;
    let vunit = f.ascii("VERTUNIT", 48).emit()?;
    let hunit = f.ascii("HORUNIT", 48).emit()?;
    f.f32("HORIZ_UNCERTAINTY").emit()?;
    let seconds = f.f64("TRIGGER_TIME seconds").emit()?;
    let minutes = f.u8("TRIGGER_TIME minutes").emit()?;
    let hours = f.u8("TRIGGER_TIME hours").emit()?;
    let days = f.u8("TRIGGER_TIME days").emit()?;
    let months = f.u8("TRIGGER_TIME months").emit()?;
    let year = f.u16("TRIGGER_TIME year").emit()?;
    f.u16("TRIGGER_TIME unused").emit()?;
    f.f32("ACQ_DURATION").emit()?;
    for n in [
        "RECORD_TYPE",
        "PROCESSING_DONE",
        "RESERVED5",
        "RIS_SWEEPS",
        "TIMEBASE",
        "VERT_COUPLING",
    ] {
        f.u16(n).emit()?;
    }
    f.f32("PROBE_ATT").emit()?;
    f.u16("FIXED_VERT_GAIN").emit()?;
    f.u16("BANDWIDTH_LIMIT").emit()?;
    f.f32("VERTICAL_VERNIER").emit()?;
    f.f32("ACQ_VERT_OFFSET").emit()?;
    f.u16("WAVE_SOURCE").emit()?;
    let mut at = start.saturating_add(desc_len.into());
    for (name, len) in [
        ("User text", user),
        ("Trigger time array", trig),
        ("RIS time array", ris),
        ("Wave array 1", wave1),
        ("Wave array 2", wave2),
    ] {
        if len > 0 {
            cx.emit(Node::new(name).span(file.sub(at, len.into())));
        }
        at = at.saturating_add(len.into());
    }
    cx.annotate(format!(
        "LeCroy {} waveform {}{}, {count} {}-byte point(s), Δt {interval} {}, gain {gain} {}, triggered {year:04}-{months:02}-{days:02} {hours:02}:{minutes:02}:{seconds:06.3}",
        template.trim_end_matches('\0'),
        label.trim_end_matches(['\0', ' ']),
        if instrument.trim_end_matches('\0').is_empty() { String::new() } else { format!(" from {}", instrument.trim_end_matches('\0')) },
        if comm_type == 0 { 1 } else { 2 },
        hunit.trim_end_matches('\0'),
        vunit.trim_end_matches('\0')
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// FST (GTKWave Fast Signal Trace)

declare_format!(pub FST = "fst", "Fast Signal Trace (FST) waveform", ["fst"], "application/x-fst",
    Probe::Magic(&[(0, b"\x00\x00\x00\x00\x00\x00\x00\x01\x49")]), fst);

const FST_BLOCKS: EnumTable = &[
    (0, "HDR"),
    (1, "VCDATA"),
    (2, "BLACKOUT"),
    (3, "GEOM"),
    (4, "HIER"),
    (5, "VCDATA_DYN_ALIAS"),
    (6, "HIER_LZ4"),
    (7, "HIER_LZ4DUO"),
    (8, "VCDATA_DYN_ALIAS2"),
    (254, "ZWRAPPER"),
    (255, "SKIP"),
];
const FST_FILETYPES: EnumTable = &[(0, "Verilog"), (1, "VHDL"), (2, "Verilog/VHDL")];

async fn fst(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut blocks = 0u32;
    let mut summary = String::new();
    while cur.remaining() >= 9 {
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        let start = cur.pos();
        let kind = cur.u8().await?;
        let len = cur.u64().await?;
        let body = file.sub(start.saturating_add(9), len.saturating_sub(8));
        let name = lookup(FST_BLOCKS, kind.into()).unwrap_or("unknown");
        let mut node = Node::new(name)
            .span(file.sub(start, len.saturating_add(1)))
            .value(uint(len));
        if kind == 0 {
            let b = cx.block(body.sub(0, 321)).await?;
            let mut f = Fields::new(&b, BE);
            let st = f.u64("Start time").get()?;
            let et = f.u64("End time").get()?;
            f.skip(16);
            let scopes = f.u64("Scopes").get()?;
            let vars = f.u64("Hierarchy vars").get()?;
            f.skip(16);
            let ts = f.int::<i8>("Timescale").get()?;
            let version = f.ascii("Version", 128).get()?;
            summary = format!(
                "{}, time {st}–{et} ×10^{ts} s, {scopes} scope(s), {vars} variable(s)",
                version.trim_end_matches('\0'),
            );
            node = node.lazy(fst_header, body);
        } else if kind == 4 {
            // HIER: uncompressed length, then a gzip stream.
            node = node.lazy(fst_hier, (input, body));
        }
        cx.push(node).await;
        blocks = blocks.saturating_add(1);
        cur.seek(start.saturating_add(1).saturating_add(len.max(8)));
    }
    cx.annotate(format!("FST waveform, {blocks} block(s); {summary}"));
    Ok(())
}

async fn fst_header(cx: Cx, body: Span) -> Result<()> {
    let b = cx.block(body.sub(0, 321)).await?;
    let mut f = Fields::emitting(&cx, &b, BE);
    f.u64("Start time").emit()?;
    f.u64("End time").emit()?;
    f.f64("Endianness test (e)")
        .desc("2.718281828… in the writer's byte order")
        .emit()?;
    f.u64("Writer memory use").emit()?;
    f.u64("Scopes").emit()?;
    f.u64("Hierarchy variables").emit()?;
    f.u64("Variables").emit()?;
    f.u64("Value change sections").emit()?;
    f.int::<i8>("Timescale (10^n s)").emit()?;
    f.ascii("Writer version", 128).emit()?;
    f.ascii("Date", 119).emit()?;
    f.u8("File type").enumeration(FST_FILETYPES).emit()?;
    f.u64("Time zero").emit()?;
    Ok(())
}

async fn fst_hier(cx: Cx, (input, body): (Input, Span)) -> Result<()> {
    let b = cx.read(body.sub(0, 8)).await?;
    cx.emit(
        Node::new("Uncompressed length")
            .span(body.sub(0, 8))
            .value(uint(crate::bytes::u64_be(&b, 0).unwrap_or(0))),
    );
    cx.emit(embedded("Hierarchy (gzip)", input.nested(body.tail(8))));
    Ok(())
}
