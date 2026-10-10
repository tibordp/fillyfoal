//! Scientific-instrument and lab data: flow cytometry (FCS), mass
//! spectrometry (Thermo RAW), electrophysiology (ABF, EDF/BDF, GDF, Intan,
//! Blackrock NEV/NSx, Plexon, BrainVision, Neuralynx), LabVIEW TDMS, and
//! machine-learning data (MNIST IDX).

use super::{field_text, kv_spans, systemtime};
use crate::bytes::{to_u64, to_usize, u16_le, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::lines::{
    Lines, contains, float, float32, hex, int, number, preview, summarize, text, uint,
};
use crate::formats::util::pace::{Resumable, run_paced};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// FCS (Flow Cytometry Standard)

fn fcs_probe(h: &Head<'_>) -> bool {
    ["FCS2.0", "FCS3.0", "FCS3.1", "FCS3.2"]
        .iter()
        .any(|v| h.at(0, v.as_bytes()))
        && h.at(6, b"    ")
}

declare_format!(pub FCS = "fcs", "Flow Cytometry Standard (FCS)", ["fcs", "lmd"], "application/vnd.isac.fcs",
    Probe::Custom(fcs_probe), fcs);

/// One TEXT keyword: key, value, and the span from key to value.
type FcsPair = (String, String, Span);

/// Splits an FCS TEXT segment into (key, value, span) using its delimiter,
/// in bounded steps.
struct FcsPairs<'a> {
    data: &'a [u8],
    span: Span,
    i: usize,
    /// The field being read (delimiter escapes resolved) and where it starts.
    cur: Vec<u8>,
    start: usize,
    /// Fields seen, and a key still waiting for its value.
    fields: usize,
    key: Option<(Vec<u8>, usize)>,
    out: Vec<FcsPair>,
}

impl<'a> FcsPairs<'a> {
    fn new(data: &'a [u8], span: Span) -> Self {
        FcsPairs {
            data,
            span,
            i: 1,
            cur: Vec::new(),
            start: 1,
            fields: 0,
            key: None,
            out: Vec::new(),
        }
    }

    /// A field ends at `end`: it is a key, or the value completing a pair.
    fn field(&mut self, end: usize) -> u64 {
        let field = std::mem::take(&mut self.cur);
        self.fields = self.fields.saturating_add(1);
        let Some((k, ks)) = self.key.take() else {
            self.key = Some((field, self.start));
            return 0;
        };
        let work = to_u64(k.len().saturating_add(field.len()));
        self.out.push((
            String::from_utf8_lossy(&k).trim().to_owned(),
            String::from_utf8_lossy(&field).into_owned(),
            self.span.sub(to_u64(ks), to_u64(end.saturating_sub(ks))),
        ));
        work
    }
}

impl Resumable for FcsPairs<'_> {
    type Output = Vec<FcsPair>;

    fn step(&mut self, budget: u64) -> bool {
        let data = self.data;
        let Some(&delim) = data.first() else {
            return true;
        };
        let mut left = budget;
        while left > 0 {
            left = left.saturating_sub(1);
            let i = self.i;
            let Some(&b) = data.get(i) else {
                return true;
            };
            // Fields are separated by single delimiters; doubled ones are escapes.
            if b == delim {
                if data.get(i.saturating_add(1)) == Some(&delim) {
                    self.cur.push(delim);
                    self.i = i.saturating_add(2);
                    continue;
                }
                left = left.saturating_sub(self.field(i));
                self.start = i.saturating_add(1);
            } else {
                self.cur.push(b);
            }
            self.i = i.saturating_add(1);
            if self.fields > 200_000 {
                return true;
            }
        }
        false
    }

    fn finish(self) -> Vec<FcsPair> {
        self.out
    }
}

/// TEXT keywords (in upper case) to the first value given for them.
type FcsKeys<'a> = std::collections::BTreeMap<String, &'a str>;

async fn fcs_keys<'a>(cx: &Cx, pairs: &'a [(String, String, Span)]) -> FcsKeys<'a> {
    let mut keys = FcsKeys::new();
    for (i, (k, v, _)) in pairs.iter().enumerate() {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        keys.entry(k.to_ascii_uppercase()).or_insert(v.as_str());
    }
    keys
}

fn fcs_get<'a>(keys: &FcsKeys<'a>, key: &str) -> Option<&'a str> {
    keys.get(&key.to_ascii_uppercase()).map(|v| v.trim())
}

async fn fcs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 58)).await?;
    let version = field_text(head.get(..6).unwrap_or_default());
    cx.emit(
        Node::new("Version")
            .span(file.sub(0, 6))
            .value(text(version.clone())),
    );
    let mut offsets = [0u64; 6];
    let names = [
        "TEXT begin",
        "TEXT end",
        "DATA begin",
        "DATA end",
        "ANALYSIS begin",
        "ANALYSIS end",
    ];
    for (i, name) in names.iter().enumerate() {
        let at = 10usize.saturating_add(i.saturating_mul(8));
        let v = field_text(head.get(at..at.saturating_add(8)).unwrap_or_default())
            .parse()
            .unwrap_or(0u64);
        if let Some(slot) = offsets.get_mut(i) {
            *slot = v;
        }
        cx.emit(
            Node::new(*name)
                .span(file.sub(to_u64(at), 8))
                .value(uint(v)),
        );
    }
    let [text_begin, text_end, mut data_begin, mut data_end, _, _] = offsets;
    let text_span = file.sub(
        text_begin,
        text_end.saturating_sub(text_begin).saturating_add(1),
    );
    let data = cx
        .read_avail(text_span.sub(0, cx.limits().max_read))
        .await?;
    let pairs = run_paced(&cx, FcsPairs::new(&data, text_span)).await;
    let keys = fcs_keys(&cx, &pairs).await;
    // Large files record the DATA offsets only in TEXT.
    if data_begin == 0 && data_end == 0 {
        data_begin = fcs_get(&keys, "$BEGINDATA")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        data_end = fcs_get(&keys, "$ENDDATA")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
    }
    let params: u64 = fcs_get(&keys, "$PAR")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let events: u64 = fcs_get(&keys, "$TOT")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let datatype = fcs_get(&keys, "$DATATYPE").unwrap_or("?").to_owned();
    let byteord = fcs_get(&keys, "$BYTEORD").unwrap_or("").to_owned();
    let cytometer = fcs_get(&keys, "$CYT").unwrap_or("").to_owned();
    let channels: Vec<String> = (1..=params.min(1000))
        .map(|i| fcs_get(&keys, &format!("$P{i}N")).unwrap_or("?").to_owned())
        .collect();
    let bits: Vec<u64> = (1..=params.min(1000))
        .map(|i| {
            fcs_get(&keys, &format!("$P{i}B"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        })
        .collect();
    let n = pairs.len();
    cx.emit(
        Node::new("TEXT")
            .span(text_span)
            .summary(format!("{n} keyword(s)"))
            .lazy(kv_spans, pairs),
    );
    let data_span = file.sub(
        data_begin,
        data_end.saturating_sub(data_begin).saturating_add(1),
    );
    if data_end > data_begin {
        let endian = if byteord.starts_with("1,2") { LE } else { BE };
        let fixed = datatype == "F"
            || datatype == "D"
            || (datatype == "I" && bits.iter().all(|&b| b == 8 || b == 16 || b == 32));
        let mut node = Node::new("DATA").span(data_span).summary(format!(
            "{events} event(s) × {params} parameter(s), type {datatype}"
        ));
        if fixed && params > 0 {
            node = node.lazy(
                fcs_events,
                (
                    data_span,
                    datatype.clone(),
                    bits.clone(),
                    channels.clone(),
                    endian,
                ),
            );
        }
        cx.emit(node);
    }
    cx.annotate(format!(
        "{version}, {events} event(s), {params} parameter(s) ({}){}",
        preview(&channels.join(", "), 80),
        if cytometer.is_empty() {
            String::new()
        } else {
            format!(", {cytometer}")
        }
    ));
    Ok(())
}

async fn fcs_events(
    cx: Cx,
    (span, datatype, bits, channels, endian): (Span, String, Vec<u64>, Vec<String>, Endian),
) -> Result<()> {
    let widths: Vec<u64> = match datatype.as_str() {
        "F" => vec![4; bits.len()],
        "D" => vec![8; bits.len()],
        _ => bits.iter().map(|b| b / 8).collect(),
    };
    let size: u64 = widths.iter().sum();
    if size == 0 {
        return Ok(());
    }
    cx.set_count(Count::Exact(span.len.checked_div(size).unwrap_or(0)));
    let mut at = 0u64;
    let mut index = 0u64;
    while at.saturating_add(size) <= span.len {
        cx.progress_in(span, span.offset.saturating_add(at));
        let event = span.sub(at, size);
        let b = cx.read(event).await?;
        let mut values = Vec::new();
        let mut off = 0usize;
        for &w in &widths {
            let bytes = b
                .get(off..off.saturating_add(to_usize(w)))
                .unwrap_or_default();
            let v = match (datatype.as_str(), w) {
                ("F", _) => f64::from(f32::from_bits(read_uint(bytes, endian) as u32)),
                ("D", _) => f64::from_bits(read_uint(bytes, endian)),
                _ => read_uint(bytes, endian) as f64,
            };
            values.push(v);
            off = off.saturating_add(to_usize(w));
        }
        let shown: Vec<String> = channels
            .iter()
            .zip(&values)
            .take(6)
            .map(|(c, v)| format!("{c}={v}"))
            .collect();
        cx.push(
            Node::new(format!("Event {index}"))
                .span(event)
                .summary(shown.join(" "))
                .lazy(fcs_event, (event, widths.clone(), channels.clone(), values)),
        )
        .await;
        at = at.saturating_add(size);
        index = index.saturating_add(1);
    }
    Ok(())
}

/// An unsigned integer from the first (up to) 8 bytes of `b`.
fn read_uint(b: &[u8], endian: Endian) -> u64 {
    let b = b.get(..8).unwrap_or(b);
    match endian {
        Endian::Big => crate::formats::util::datakit::be_uint(b),
        Endian::Little => crate::formats::util::datakit::le_uint(b),
    }
}

async fn fcs_event(
    cx: Cx,
    (span, widths, channels, values): (Span, Vec<u64>, Vec<String>, Vec<f64>),
) -> Result<()> {
    let mut at = 0u64;
    for ((w, c), v) in widths.iter().zip(&channels).zip(&values) {
        cx.emit(Node::new(c.clone()).span(span.sub(at, *w)).value(float(*v)));
        at = at.saturating_add(*w);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Thermo Fisher (Finnigan) RAW

declare_format!(pub THERMO_RAW = "thermo-raw", "Thermo Fisher mass spectrometry raw data", ["raw"], "application/x-thermo-raw",
    Probe::Magic(&[(0, b"\x01\xa1F\0i\0n\0n\0i\0g\0a\0n\0")]), thermo_raw);

record! {
    pub struct AuditTag {
        time: u64 "Time" .filetime(),
        user: utf16[25] "User",
        machine: utf16[25] "Machine",
        unknown: u32 "Unknown",
    }
}

async fn thermo_raw(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x28)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Magic").hex().emit()?;
    f.utf16("Signature", 9).emit()?;
    for _ in 0..4 {
        f.u32("Unknown").emit()?;
    }
    let version = f.u32("Version").emit()?;
    let created: AuditTag = read_record(&cx, file.sub(0x28, AuditTag::SIZE), LE).await?;
    cx.emit(AuditTag::node(
        "Created",
        file.sub(0x28, AuditTag::SIZE),
        LE,
    ));
    cx.emit(AuditTag::node(
        "Modified",
        file.sub(0x28u64.saturating_add(AuditTag::SIZE), AuditTag::SIZE),
        LE,
    ));
    let tag_at = 0x28u64
        .saturating_add(AuditTag::SIZE.saturating_mul(2))
        .saturating_add(64);
    let tag = cx.block(file.sub(tag_at, 1028)).await?;
    let mut f = Fields::new(&tag, LE);
    let tag_text = f.utf16("Tag", 514).get().unwrap_or_default();
    cx.emit(
        Node::new("File tag")
            .span(file.sub(tag_at, 1028))
            .value(text(tag_text.trim_end_matches('\0'))),
    );
    cx.emit(
        Node::new("Body")
            .span(file.tail(tag_at.saturating_add(1028)))
            .diag(Diagnostic::unsupported("Thermo RAW sequence/scan data")),
    );
    let user = created.user.trim_end_matches('\0');
    cx.annotate(format!(
        "Thermo RAW v{version}{}",
        if user.is_empty() {
            String::new()
        } else {
            format!(", created by {user}")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Axon Binary Format (ABF 1 and 2)

declare_format!(pub ABF = "abf", "Axon Binary Format (ABF 1)", ["abf"], "application/x-abf",
    Probe::Custom(|h| h.at(0, b"ABF ") && u32_le(h.data, 4).is_some_and(|v| (0.5..3.0).contains(&f32::from_bits(v)))), abf1);
declare_format!(pub ABF2 = "abf2", "Axon Binary Format (ABF 2)", ["abf"], "application/x-abf",
    Probe::Magic(&[(0, b"ABF2")]), abf2);

const ABF_MODES: EnumTable = &[
    (1, "event-driven, variable length"),
    (2, "oscilloscope, loss-free"),
    (3, "gap-free"),
    (4, "oscilloscope, high-speed"),
    (5, "episodic stimulation"),
];
const ABF_DATA: EnumTable = &[(0, "int16"), (1, "float32")];

record! {
    pub struct Abf1Header {
        signature: ascii[4] "lFileSignature",
        version: f32 "fFileVersionNumber",
        mode: u16 "nOperationMode" .enumeration(ABF_MODES),
        acq_length: u32 "lActualAcqLength" .desc("Samples acquired"),
        ignored: u16 "nNumPointsIgnored",
        episodes: u32 "lActualEpisodes",
        date: u32 "lFileStartDate" .desc("YYYYMMDD"),
        time: u32 "lFileStartTime" .desc("Seconds since midnight"),
        stopwatch: u32 "lStopwatchTime",
        header_version: f32 "fHeaderVersionNumber",
        file_type: u16 "nFileType",
        ms_bin: u16 "nMSBinFormat",
        data_ptr: u32 "lDataSectionPtr" .desc("In 512-byte blocks"),
        tag_ptr: u32 "lTagSectionPtr",
        tags: u32 "lNumTagEntries",
    }
}

async fn abf1(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: Abf1Header = read_record(&cx, file.sub(0, Abf1Header::SIZE), LE).await?;
    cx.emit(Abf1Header::node(
        "Header",
        file.sub(0, Abf1Header::SIZE),
        LE,
    ));
    let more = cx.block(file.sub(100, 50)).await?;
    let mut f = Fields::new(&more, LE);
    let format = f.u16("nDataFormat").get()?;
    f.skip(18);
    let channels = f.u16("nADCNumChannels").get()?;
    let interval = f.f32("fADCSampleInterval").get()?;
    cx.emit(
        Node::new("Acquisition")
            .span(file.sub(100, 50))
            .lazy(abf1_acq, file.sub(100, 50)),
    );
    let names = cx.read_avail(file.sub(442, 160)).await?;
    let units = cx.read_avail(file.sub(602, 128)).await?;
    let list: Vec<String> = (0..usize::from(channels.min(16)))
        .map(|i| {
            let n = field_text(
                names
                    .get(i.saturating_mul(10)..i.saturating_mul(10).saturating_add(10))
                    .unwrap_or_default(),
            );
            let u = field_text(
                units
                    .get(i.saturating_mul(8)..i.saturating_mul(8).saturating_add(8))
                    .unwrap_or_default(),
            );
            format!("{n} ({u})")
        })
        .collect();
    cx.emit(
        Node::new("ADC channels")
            .span(file.sub(442, 288))
            .value(text(list.join(", "))),
    );
    let sample = if format == 1 { 4 } else { 2 };
    let data = file.sub(
        u64::from(h.data_ptr).saturating_mul(512),
        u64::from(h.acq_length).saturating_mul(sample),
    );
    cx.emit(Node::new("Data").span(data).summary(format!(
        "{} {} samples",
        h.acq_length,
        lookup(ABF_DATA, format.into()).unwrap_or("?")
    )));
    let rate = if interval > 0.0 {
        1e6 / f64::from(interval) / f64::from(channels.max(1))
    } else {
        0.0
    };
    cx.annotate(format!(
        "ABF {:.2}, {}, {channels} channel(s) at {rate:.0} Hz, {} episode(s)",
        h.version,
        lookup(ABF_MODES, h.mode.into()).unwrap_or("unknown mode"),
        h.episodes
    ));
    Ok(())
}

async fn abf1_acq(cx: Cx, span: Span) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &b, LE);
    f.u16("nDataFormat").enumeration(ABF_DATA).emit()?;
    f.u16("nSimultaneousScan").emit()?;
    f.u32("lStatisticsConfigPtr").emit()?;
    f.u32("lAnnotationSectionPtr").emit()?;
    f.u32("lNumAnnotations").emit()?;
    f.bytes("Unused", 2).emit()?;
    f.u16("channel_count_acquired").emit()?;
    f.u16("nADCNumChannels").emit()?;
    f.f32("fADCSampleInterval")
        .desc("Microseconds, all channels")
        .emit()?;
    f.f32("fADCSecondSampleInterval").emit()?;
    f.f32("fSynchTimeUnit").emit()?;
    f.f32("fSecondsPerRun").emit()?;
    f.u32("lNumSamplesPerEpisode").emit()?;
    f.u32("lPreTriggerSamples").emit()?;
    Ok(())
}

const ABF2_SECTIONS: [&str; 18] = [
    "Protocol",
    "ADC",
    "DAC",
    "Epoch",
    "ADCPerDAC",
    "EpochPerDAC",
    "UserList",
    "StatsRegion",
    "Math",
    "Strings",
    "Data",
    "Tag",
    "Scope",
    "Delta",
    "VoiceTag",
    "SynchArray",
    "Annotation",
    "Stats",
];

record! {
    pub struct Abf2Header {
        signature: ascii[4] "fFileSignature",
        version: u32 "fFileVersionNumber" .hex().desc("Version digits, least significant first"),
        info_size: u32 "uFileInfoSize",
        episodes: u32 "lActualEpisodes",
        date: u32 "uFileStartDate" .desc("YYYYMMDD"),
        time_ms: u32 "uFileStartTimeMS",
        stopwatch: u32 "uStopwatchTime",
        file_type: u16 "nFileType",
        data_format: u16 "nDataFormat" .enumeration(ABF_DATA),
        simultaneous: u16 "nSimultaneousScan",
        crc_enable: u16 "nCRCEnable",
        crc: u32 "uFileCRC" .hex(),
        guid: guid "FileGUID",
        creator_version: u32 "uCreatorVersion" .hex(),
        creator_name: u32 "uCreatorNameIndex",
        modifier_version: u32 "uModifierVersion" .hex(),
        modifier_name: u32 "uModifierNameIndex",
        protocol_path: u32 "uProtocolPathIndex",
    }
}

record! {
    pub struct Abf2Section {
        block: u32 "uBlockIndex" .desc("Offset in 512-byte blocks"),
        bytes: u32 "uBytes" .desc("Bytes per entry"),
        entries: u64 "llNumEntries",
    }
}

async fn abf2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: Abf2Header = read_record(&cx, file.sub(0, Abf2Header::SIZE), LE).await?;
    cx.emit(Abf2Header::node(
        "Header",
        file.sub(0, Abf2Header::SIZE),
        LE,
    ));
    let mut sections = Vec::new();
    for (i, name) in ABF2_SECTIONS.iter().enumerate() {
        let at = Abf2Header::SIZE.saturating_add(to_u64(i).saturating_mul(Abf2Section::SIZE));
        let s: Abf2Section = read_record(&cx, file.sub(at, Abf2Section::SIZE), LE).await?;
        sections.push((*name, s));
    }
    cx.emit(
        Node::new("Section map")
            .span(file.sub(Abf2Header::SIZE, Abf2Section::SIZE.saturating_mul(18)))
            .lazy(abf2_map, file),
    );
    let mut strings = Vec::new();
    let mut channels = 0u64;
    let mut samples = 0u64;
    for (name, s) in &sections {
        if s.block == 0 {
            continue;
        }
        let span = file.sub(
            u64::from(s.block).saturating_mul(512),
            u64::from(s.bytes).saturating_mul(s.entries),
        );
        let node = Node::new(format!("{name} section"))
            .span(span)
            .summary(format!("{} × {} bytes", s.entries, s.bytes));
        match *name {
            "Strings" => {
                let raw = cx.read_avail(span.sub(0, 0x10000)).await?;
                strings = raw
                    .split(|&b| b == 0)
                    .filter(|s| s.len() > 1 && s.iter().all(|&c| (0x20..0x7f).contains(&c)))
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                cx.emit(
                    Node::new("Strings section")
                        .span(span)
                        .value(uint(to_u64(strings.len())))
                        .lazy(abf2_strings, strings.clone()),
                );
            }
            "ADC" => {
                channels = s.entries;
                cx.emit(node);
            }
            "Data" => {
                samples = s.entries;
                cx.emit(node);
            }
            _ => cx.emit(node),
        }
    }
    let v = h.version.to_le_bytes();
    let creator = strings.first().cloned().unwrap_or_default();
    cx.annotate(format!(
        "ABF {}.{}.{}, {} sample(s), {channels} ADC channel(s), {} episode(s){}",
        v.get(3).unwrap_or(&0),
        v.get(2).unwrap_or(&0),
        v.get(1).unwrap_or(&0),
        samples,
        h.episodes,
        if creator.is_empty() {
            String::new()
        } else {
            format!(", {creator}")
        }
    ));
    Ok(())
}

async fn abf2_map(cx: Cx, file: Span) -> Result<()> {
    for (i, name) in ABF2_SECTIONS.iter().enumerate() {
        let at = Abf2Header::SIZE.saturating_add(to_u64(i).saturating_mul(Abf2Section::SIZE));
        cx.emit(Abf2Section::node(
            *name,
            file.sub(at, Abf2Section::SIZE),
            LE,
        ));
    }
    Ok(())
}

async fn abf2_strings(cx: Cx, strings: Vec<String>) -> Result<()> {
    for (i, s) in strings.into_iter().enumerate() {
        cx.push(Node::new(format!("String {i}")).value(text(s)))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EDF / EDF+ / BDF (European Data Format, BioSemi)

fn edf_probe(h: &Head<'_>) -> bool {
    let date = h.data.get(168..176).unwrap_or_default();
    h.at(0, b"0       ")
        && date.len() == 8
        && date.iter().enumerate().all(|(i, &b)| {
            if i == 2 || i == 5 {
                b == b'.' || b == b':'
            } else {
                b.is_ascii_digit() || b == b' '
            }
        })
}

declare_format!(pub EDF = "edf", "European Data Format (EDF/EDF+)", ["edf", "rec"], "application/x-edf",
    Probe::Custom(edf_probe), edf);
declare_format!(pub BDF = "biosemi-bdf", "BioSemi Data Format (BDF)", ["bdf"], "application/x-bdf",
    Probe::Magic(&[(0, b"\xffBIOSEMI")]), bdf);

/// Per-signal header fields: (name, width).
const EDF_SIGNAL_FIELDS: [(&str, u64); 10] = [
    ("Label", 16),
    ("Transducer", 80),
    ("Physical dimension", 8),
    ("Physical minimum", 8),
    ("Physical maximum", 8),
    ("Digital minimum", 8),
    ("Digital maximum", 8),
    ("Prefiltering", 80),
    ("Samples per record", 8),
    ("Reserved", 32),
];

#[derive(Clone, Debug)]
struct EdfSignal {
    label: String,
    samples: u64,
    dimension: String,
}

async fn edf(cx: Cx, input: Input) -> Result<()> {
    edf_like(cx, input, 2).await
}

async fn bdf(cx: Cx, input: Input) -> Result<()> {
    edf_like(cx, input, 3).await
}

async fn edf_like(cx: Cx, input: Input, sample_size: u64) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 256)).await?;
    let fields: [(&str, usize, usize); 10] = [
        ("Version", 0, 8),
        ("Patient", 8, 80),
        ("Recording", 88, 80),
        ("Start date", 168, 8),
        ("Start time", 176, 8),
        ("Header bytes", 184, 8),
        ("Reserved", 192, 44),
        ("Data records", 236, 8),
        ("Record duration (s)", 244, 8),
        ("Signals", 252, 4),
    ];
    let mut values = Vec::new();
    for (name, at, len) in fields {
        let raw = head.get(at..at.saturating_add(len)).unwrap_or_default();
        let v = if at == 0 && raw.first() == Some(&0xff) {
            format!("\\xff{}", field_text(raw.get(1..).unwrap_or_default()))
        } else {
            field_text(raw)
        };
        cx.emit(
            Node::new(name)
                .span(file.sub(to_u64(at), to_u64(len)))
                .value(if at >= 184 && at != 192 {
                    number(&v)
                } else {
                    text(v.clone())
                }),
        );
        values.push(v);
    }
    let get = |i: usize| values.get(i).cloned().unwrap_or_default();
    let ns: u64 = get(9).parse().unwrap_or(0);
    let records: i64 = get(7).parse().unwrap_or(-1);
    let duration: f64 = get(8).parse().unwrap_or(0.0);
    let reserved = get(6);
    let header_bytes = 256u64.saturating_add(ns.saturating_mul(256));
    let sig_span = file.sub(256, ns.saturating_mul(256));
    let sig_data = cx.read_avail(sig_span.sub(0, cx.limits().max_read)).await?;
    let column = |field: usize, i: u64| -> String {
        let before: u64 = EDF_SIGNAL_FIELDS
            .iter()
            .take(field)
            .map(|(_, w)| w.saturating_mul(ns))
            .sum();
        let w = EDF_SIGNAL_FIELDS.get(field).map_or(0, |(_, w)| *w);
        let at = to_usize(before.saturating_add(w.saturating_mul(i)));
        field_text(
            sig_data
                .get(at..at.saturating_add(to_usize(w)))
                .unwrap_or_default(),
        )
    };
    let signals: Vec<EdfSignal> = (0..ns.min(4096))
        .map(|i| EdfSignal {
            label: column(0, i),
            samples: column(8, i).parse().unwrap_or(0),
            dimension: column(2, i),
        })
        .collect();
    cx.emit(
        Node::new("Signal headers")
            .span(sig_span)
            .value(uint(ns))
            .lazy(edf_signals, (sig_span, ns)),
    );
    let record_size: u64 = signals
        .iter()
        .map(|s| s.samples.saturating_mul(sample_size))
        .sum();
    let data = file.tail(header_bytes);
    if record_size > 0 {
        cx.emit(
            Node::new("Data records")
                .span(data)
                .summary(format!(
                    "{} × {record_size} bytes",
                    data.len.checked_div(record_size).unwrap_or(0)
                ))
                .lazy(
                    edf_records,
                    (data, signals.clone(), record_size, sample_size),
                ),
        );
    }
    let annotations = signals.iter().any(|s| s.label.contains("Annotations"));
    let kind = if sample_size == 3 {
        "BDF"
    } else if reserved.starts_with("EDF+C") {
        "EDF+ (continuous)"
    } else if reserved.starts_with("EDF+D") {
        "EDF+ (discontinuous)"
    } else {
        "EDF"
    };
    let labels: Vec<&str> = signals.iter().map(|s| s.label.as_str()).collect();
    cx.annotate(format!(
        "{kind}, {ns} signal(s) ({}), {} record(s) of {duration} s, started {} {}{}",
        preview(&labels.join(", "), 80),
        if records < 0 {
            "unknown".to_owned()
        } else {
            records.to_string()
        },
        get(3),
        get(4),
        if annotations {
            ", with annotations"
        } else {
            ""
        }
    ));
    Ok(())
}

async fn edf_signals(cx: Cx, (span, ns): (Span, u64)) -> Result<()> {
    let data = cx.read_avail(span.sub(0, cx.limits().max_read)).await?;
    for i in 0..ns.min(4096) {
        let mut parts = Vec::new();
        let mut before = 0u64;
        for (name, w) in EDF_SIGNAL_FIELDS {
            let at = before.saturating_add(w.saturating_mul(i));
            parts.push((
                name,
                span.sub(at, w),
                field_text(
                    data.get(to_usize(at)..to_usize(at.saturating_add(w)))
                        .unwrap_or_default(),
                ),
            ));
            before = before.saturating_add(w.saturating_mul(ns));
        }
        let label = parts.first().map(|p| p.2.clone()).unwrap_or_default();
        let dim = parts.get(2).map(|p| p.2.clone()).unwrap_or_default();
        let rate = parts.get(8).map(|p| p.2.clone()).unwrap_or_default();
        cx.push(
            Node::new(if label.is_empty() {
                format!("Signal {i}")
            } else {
                label
            })
            .summary(format!(
                "{rate} samples/record{}",
                if dim.is_empty() {
                    String::new()
                } else {
                    format!(", {dim}")
                }
            ))
            .lazy(edf_signal, parts),
        )
        .await;
    }
    Ok(())
}

async fn edf_signal(cx: Cx, parts: Vec<(&'static str, Span, String)>) -> Result<()> {
    for (i, (name, span, v)) in parts.into_iter().enumerate() {
        cx.emit(
            Node::new(name)
                .span(span)
                .value(if (3..=6).contains(&i) || i == 8 {
                    number(&v)
                } else {
                    text(v)
                }),
        );
    }
    Ok(())
}

async fn edf_records(
    cx: Cx,
    (data, signals, record_size, sample_size): (Span, Vec<EdfSignal>, u64, u64),
) -> Result<()> {
    let count = data.len.checked_div(record_size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for r in 0..count {
        let span = data.sub(r.saturating_mul(record_size), record_size);
        cx.push(
            Node::new(format!("Record {r}"))
                .span(span)
                .lazy(edf_record, (span, signals.clone(), sample_size)),
        )
        .await;
    }
    Ok(())
}

async fn edf_record(
    cx: Cx,
    (span, signals, sample_size): (Span, Vec<EdfSignal>, u64),
) -> Result<()> {
    let mut at = 0u64;
    for s in signals {
        let len = s.samples.saturating_mul(sample_size);
        let part = span.sub(at, len);
        let mut node = Node::new(s.label.clone()).span(part);
        if s.label.contains("Annotations") {
            node = node.lazy(edf_tals, part);
        } else {
            let b = cx
                .read_avail(part.sub(0, sample_size.saturating_mul(8)))
                .await?;
            let shown: Vec<String> = b
                .chunks(to_usize(sample_size))
                .filter(|c| to_u64(c.len()) == sample_size)
                .map(|c| {
                    if sample_size == 3 {
                        let v = i32::from_le_bytes([
                            c.first().copied().unwrap_or(0),
                            c.get(1).copied().unwrap_or(0),
                            c.get(2).copied().unwrap_or(0),
                            0,
                        ]);
                        ((v << 8) >> 8).to_string()
                    } else {
                        crate::bytes::i16_le(c, 0).unwrap_or(0).to_string()
                    }
                })
                .collect();
            node = node.summary(format!(
                "{} sample(s){}: {}{}",
                s.samples,
                if s.dimension.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", s.dimension)
                },
                shown.join(", "),
                if s.samples > 8 { ", …" } else { "" }
            ));
        }
        cx.emit(node);
        at = at.saturating_add(len);
    }
    Ok(())
}

/// EDF+ time-stamped annotation lists: `+onset[\x15duration]\x14text\x14…\0`.
async fn edf_tals(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let mut at = 0usize;
    for tal in data.split(|&b| b == 0) {
        let len = tal.len();
        if !tal.is_empty() {
            let mut parts = tal.split(|&b| b == 0x14);
            let timing = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
            let (onset, duration) = timing
                .split_once('\x15')
                .map_or((timing.clone(), String::new()), |(o, d)| {
                    (o.to_owned(), d.to_owned())
                });
            let texts: Vec<String> = parts
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .filter(|t| !t.is_empty())
                .collect();
            let node = Node::new(format!("{onset} s"))
                .span(span.sub(to_u64(at), to_u64(len)))
                .value(text(if texts.is_empty() {
                    "(record start)".to_owned()
                } else {
                    texts.join("; ")
                }));
            cx.push(summarize(
                node,
                if duration.is_empty() {
                    String::new()
                } else {
                    format!("duration {duration} s")
                },
            ))
            .await;
        }
        at = at.saturating_add(len).saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GDF (General Data Format for biosignals)

declare_format!(pub GDF = "gdf", "General Data Format for biomedical signals (GDF)", ["gdf"], "application/x-gdf",
    Probe::Custom(|h| h.at(0, b"GDF ") && h.data.get(4).is_some_and(u8::is_ascii_digit) && h.data.get(5) == Some(&b'.')), gdf);

const GDF_TYPES: EnumTable = &[
    (0, "char"),
    (1, "int8"),
    (2, "uint8"),
    (3, "int16"),
    (4, "uint16"),
    (5, "int32"),
    (6, "uint32"),
    (7, "int64"),
    (8, "uint64"),
    (16, "float32"),
    (17, "float64"),
    (18, "float128"),
    (279, "int24"),
    (525, "uint24"),
];

fn gdf_type_size(t: u32) -> u64 {
    match t {
        0..=2 => 1,
        3 | 4 => 2,
        5 | 6 | 16 => 4,
        7 | 8 | 17 => 8,
        18 => 16,
        279 | 525 => 3,
        _ => 0,
    }
}

/// GDF 2 timestamps: days since year 0 as a 32.32 fixed-point number.
fn gdf_time(v: u64) -> Value {
    let days = (v >> 32).cast_signed();
    let frac = (v & 0xffff_ffff) as f64 / 4_294_967_296.0;
    #[allow(clippy::cast_possible_truncation)]
    let secs = (frac * 86400.0) as i64;
    Value::Timestamp {
        unix_seconds: days
            .saturating_sub(719_529)
            .saturating_mul(86400)
            .saturating_add(secs),
    }
}

async fn gdf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 256)).await?;
    let version_text = field_text(head.data.get(..8).unwrap_or_default());
    let major = head.data.get(4).copied().unwrap_or(b'2');
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Version", 8).emit()?;
    let (ns, records, num, den, header_blocks);
    if major == b'1' {
        f.ascii("Patient", 80).emit()?;
        f.ascii("Recording", 80).emit()?;
        f.ascii("Start date/time", 16)
            .desc("YYYYMMDDhhmmsscc")
            .emit()?;
        let header_bytes = f.u64("Header bytes").emit()?;
        f.u64("Equipment provider").emit()?;
        f.u64("Laboratory").emit()?;
        f.u64("Technician").emit()?;
        f.bytes("Reserved", 20).emit()?;
        records = f.u64("Data records").emit()?;
        num = f.u32("Record duration numerator").emit()?;
        den = f.u32("Record duration denominator").emit()?;
        ns = u64::from(f.u32("Signals").emit()?);
        header_blocks = header_bytes / 256;
    } else {
        f.ascii("Patient", 66).emit()?;
        f.bytes("Reserved", 10).emit()?;
        f.u8("Smoking/alcohol/drugs/medication").hex().emit()?;
        f.u8("Weight (kg)").emit()?;
        f.u8("Height (cm)").emit()?;
        f.u8("Gender/handedness/impairment").hex().emit()?;
        f.ascii("Recording", 64).emit()?;
        f.bytes("Recording location", 16).emit()?;
        f.u64("Start date/time")
            .with(|&v, n| n.value(gdf_time(v)))
            .emit()?;
        f.u64("Birthday")
            .with(|&v, n| if v == 0 { n } else { n.value(gdf_time(v)) })
            .emit()?;
        header_blocks = u64::from(f.u16("Header length (256-byte blocks)").emit()?);
        f.bytes("Patient classification", 6).emit()?;
        f.u64("Equipment provider").hex().emit()?;
        f.bytes("Reserved", 6).emit()?;
        f.bytes("Head size (mm)", 6).emit()?;
        f.bytes("Reference electrode position", 12).emit()?;
        f.bytes("Ground electrode position", 12).emit()?;
        records = f.u64("Data records").emit()?;
        num = f.u32("Record duration numerator").emit()?;
        den = f.u32("Record duration denominator").emit()?;
        ns = u64::from(f.u16("Signals").emit()?);
        f.u16("Reserved").emit()?;
    }
    let channels = file.sub(256, ns.saturating_mul(256));
    let ch_data = cx.read_avail(channels.sub(0, cx.limits().max_read)).await?;
    // Channel fields are stored column-wise: all labels, then all transducers, ...
    let col = |offset: u64, width: u64, i: u64| -> &[u8] {
        let at = to_usize(
            offset
                .saturating_mul(ns)
                .saturating_add(width.saturating_mul(i)),
        );
        ch_data
            .get(at..at.saturating_add(to_usize(width)))
            .unwrap_or_default()
    };
    let (spr_off, type_off) = (216u64, 220u64);
    let mut labels = Vec::new();
    let mut record_size = 0u64;
    for i in 0..ns.min(4096) {
        labels.push(field_text(col(0, 16, i)));
        let spr = u64::from(u32_le(col(spr_off, 4, i), 0).unwrap_or(0));
        let t = u32_le(col(type_off, 4, i), 0).unwrap_or(0);
        record_size = record_size.saturating_add(spr.saturating_mul(gdf_type_size(t)));
    }
    cx.emit(
        Node::new("Channel headers")
            .span(channels)
            .value(uint(ns))
            .lazy(gdf_channels, (channels, ns)),
    );
    let data_at = header_blocks
        .saturating_mul(256)
        .max(256u64.saturating_add(ns.saturating_mul(256)));
    if header_blocks > ns.saturating_add(1) && major != b'1' {
        let tags = file.sub(
            256u64.saturating_add(ns.saturating_mul(256)),
            data_at.saturating_sub(256u64.saturating_add(ns.saturating_mul(256))),
        );
        cx.emit(Node::new("Variable header (tags)").span(tags));
    }
    let data = file.tail(data_at);
    cx.emit(
        Node::new("Data records")
            .span(data)
            .summary(format!("{records} × {record_size} bytes")),
    );
    let duration = if den == 0 {
        0.0
    } else {
        f64::from(num) / f64::from(den)
    };
    cx.annotate(format!(
        "{version_text}, {ns} channel(s) ({}), {records} record(s) of {duration} s",
        preview(&labels.join(", "), 80)
    ));
    Ok(())
}

async fn gdf_channels(cx: Cx, (span, ns): (Span, u64)) -> Result<()> {
    // (name, column offset per channel block, width, kind)
    const FIELDS: [(&str, u64, u64, u8); 14] = [
        ("Label", 0, 16, b's'),
        ("Transducer", 16, 80, b's'),
        ("Physical dimension", 96, 6, b's'),
        ("Physical dimension code", 102, 2, b'h'),
        ("Physical minimum", 104, 8, b'd'),
        ("Physical maximum", 112, 8, b'd'),
        ("Digital minimum", 120, 8, b'd'),
        ("Digital maximum", 128, 8, b'd'),
        ("Prefiltering", 136, 68, b's'),
        ("Lowpass (Hz)", 204, 4, b'f'),
        ("Highpass (Hz)", 208, 4, b'f'),
        ("Notch (Hz)", 212, 4, b'f'),
        ("Samples per record", 216, 4, b'i'),
        ("Data type", 220, 4, b't'),
    ];
    let data = cx.read_avail(span.sub(0, cx.limits().max_read)).await?;
    for i in 0..ns.min(4096) {
        let mut parts = Vec::new();
        for (name, off, width, kind) in FIELDS {
            let at = off
                .saturating_mul(ns)
                .saturating_add(width.saturating_mul(i));
            let b = data
                .get(to_usize(at)..to_usize(at.saturating_add(width)))
                .unwrap_or_default();
            let v = match kind {
                b's' => text(field_text(b)),
                b'h' => uint(u16_le(b, 0).unwrap_or(0).into()),
                b'd' => float(f64::from_bits(u64_le(b, 0).unwrap_or(0))),
                b'f' => float32(f32::from_bits(u32_le(b, 0).unwrap_or(0))),
                b't' => crate::formats::util::lines::enumeration(
                    GDF_TYPES,
                    u32_le(b, 0).unwrap_or(0).into(),
                    32,
                ),
                _ => uint(u32_le(b, 0).unwrap_or(0).into()),
            };
            parts.push((name, span.sub(at, width), v));
        }
        let label = match parts.first() {
            Some((_, _, Value::Text(t))) if !t.is_empty() => t.clone(),
            _ => format!("Channel {i}"),
        };
        cx.push(Node::new(label).lazy(gdf_channel, parts)).await;
    }
    Ok(())
}

async fn gdf_channel(cx: Cx, parts: Vec<(&'static str, Span, Value)>) -> Result<()> {
    for (name, span, v) in parts {
        cx.emit(Node::new(name).span(span).value(v));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Intan RHD2000

declare_format!(pub INTAN_RHD = "intan-rhd", "Intan RHD2000 recording", ["rhd"], "application/x-intan-rhd",
    Probe::Magic(&[(0, b"\x02\x27\x91\xc6")]), intan_rhd);

const RHD_SIGNAL_TYPES: EnumTable = &[
    (0, "amplifier"),
    (1, "auxiliary input"),
    (2, "supply voltage"),
    (3, "board ADC"),
    (4, "board digital in"),
    (5, "board digital out"),
];

/// Reads a Qt QString: u32 byte length (0xffffffff = null), UTF-16LE.
async fn qstring(cur: &mut Cursor<'_>) -> Result<String> {
    let len = cur.u32().await?;
    if len == u32::MAX {
        return Ok(String::new());
    }
    if len > 0x10000 {
        return Err(Diagnostic::malformed(format!("QString of {len} bytes")));
    }
    let b = cur.bytes(len.into()).await?;
    Ok(crate::text::utf16(&b, LE))
}

async fn intan_rhd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let start = cur.pos();
    cur.u32().await?;
    cx.emit(
        Node::new("Magic")
            .span(cur.since(start))
            .value(hex(0xc691_2702, 32)),
    );
    let emit_num =
        |name: &'static str, span: Span, v: Value| cx.emit(Node::new(name).span(span).value(v));
    let s = cur.pos();
    let major = cur.u16().await?;
    let minor = cur.u16().await?;
    emit_num("Version", cur.since(s), text(format!("{major}.{minor}")));
    let mut rate = 0.0f32;
    for name in [
        "Sample rate (Hz)",
        "DSP enabled",
        "Actual DSP cutoff (Hz)",
        "Actual lower bandwidth (Hz)",
        "Actual upper bandwidth (Hz)",
        "Desired DSP cutoff (Hz)",
        "Desired lower bandwidth (Hz)",
        "Desired upper bandwidth (Hz)",
        "Notch filter mode",
        "Desired impedance test frequency (Hz)",
        "Actual impedance test frequency (Hz)",
    ] {
        let s = cur.pos();
        let v = if name == "DSP enabled" || name == "Notch filter mode" {
            int(i64::from(cur.u16().await?.cast_signed()))
        } else {
            let f = cur.int::<f32>().await?;
            if name.starts_with("Sample rate") {
                rate = f;
            }
            float32(f)
        };
        emit_num(name, cur.since(s), v);
    }
    for name in ["Note 1", "Note 2", "Note 3"] {
        let s = cur.pos();
        let note = qstring(&mut cur).await?;
        emit_num(name, cur.since(s), text(note));
    }
    if (major, minor) >= (1, 1) {
        let s = cur.pos();
        let n = cur.u16().await?;
        emit_num("Temperature sensor channels", cur.since(s), uint(n.into()));
    }
    if (major, minor) >= (1, 3) {
        let s = cur.pos();
        let n = cur.u16().await?;
        emit_num("Eval board mode", cur.since(s), uint(n.into()));
    }
    if major >= 2 {
        let s = cur.pos();
        let r = qstring(&mut cur).await?;
        emit_num("Reference channel", cur.since(s), text(r));
    }
    let s = cur.pos();
    let groups = cur.u16().await?;
    emit_num("Signal groups", cur.since(s), uint(groups.into()));
    let mut amplifiers = 0u64;
    let mut total = 0u64;
    for _ in 0..groups.min(64) {
        let gs = cur.pos();
        let name = qstring(&mut cur).await?;
        let prefix = qstring(&mut cur).await?;
        let enabled = cur.u16().await?;
        let channels = cur.u16().await?;
        let amps = cur.u16().await?;
        let mut list = Vec::new();
        for _ in 0..channels {
            let cs = cur.pos();
            let native = qstring(&mut cur).await?;
            let custom = qstring(&mut cur).await?;
            cur.skip(4);
            let kind = cur.u16().await?;
            let on = cur.u16().await?;
            cur.skip(12);
            let magnitude = cur.int::<f32>().await?;
            cur.skip(4);
            list.push((native, custom, kind, on != 0, magnitude, cur.since(cs)));
            if on != 0 {
                total = total.saturating_add(1);
                if kind == 0 {
                    amplifiers = amplifiers.saturating_add(1);
                }
            }
        }
        cx.emit(
            Node::new(format!("Group {name} ({prefix})"))
                .span(cur.since(gs))
                .summary(format!(
                    "{channels} channel(s), {amps} amplifier(s){}",
                    if enabled == 0 { ", disabled" } else { "" }
                ))
                .lazy(rhd_channels, list),
        );
    }
    let header_end = cur.pos();
    cx.emit(
        Node::new("Data blocks")
            .span(file.tail(header_end))
            .summary(format!("{} bytes", file.len.saturating_sub(header_end))),
    );
    cx.annotate(format!("Intan RHD {major}.{minor}, {rate} Hz, {amplifiers} amplifier channel(s), {total} enabled channel(s) in {groups} group(s)"));
    Ok(())
}

type RhdChannel = (String, String, u16, bool, f32, Span);

async fn rhd_channels(cx: Cx, list: Vec<RhdChannel>) -> Result<()> {
    for (native, custom, kind, on, magnitude, span) in list {
        let mut node =
            Node::new(custom.clone())
                .span(span)
                .value(crate::formats::util::lines::enumeration(
                    RHD_SIGNAL_TYPES,
                    kind.into(),
                    16,
                ));
        let mut summary = format!("native {native}");
        if kind == 0 {
            summary = format!("{summary}, impedance {magnitude:.0} Ω");
        }
        if !on {
            summary = format!("{summary}, disabled");
        }
        node = node.summary(summary);
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LabVIEW TDMS

declare_format!(pub TDMS = "tdms", "LabVIEW Technical Data Management Streaming (TDMS)", ["tdms"], "application/x-tdms",
    Probe::Custom(|h| h.at(0, b"TDSm") && u32_le(h.data, 8).is_some_and(|v| v == 4712 || v == 4713)), tdms);
declare_format!(pub TDMS_INDEX = "tdms-index", "LabVIEW TDMS index", ["tdms_index"], "application/x-tdms-index",
    Probe::Custom(|h| h.at(0, b"TDSh") && u32_le(h.data, 8).is_some_and(|v| v == 4712 || v == 4713)), tdms);

const TDMS_TOC: FlagTable = &[
    flag(0x2, "kTocMetaData"),
    flag(0x4, "kTocNewObjList"),
    flag(0x8, "kTocRawData"),
    flag(0x20, "kTocInterleavedData"),
    flag(0x40, "kTocBigEndian"),
    flag(0x80, "kTocDAQmxRawData"),
];

const TDMS_TYPES: EnumTable = &[
    (0, "void"),
    (1, "i8"),
    (2, "i16"),
    (3, "i32"),
    (4, "i64"),
    (5, "u8"),
    (6, "u16"),
    (7, "u32"),
    (8, "u64"),
    (9, "f32"),
    (10, "f64"),
    (0x19, "f32 (with unit)"),
    (0x1a, "f64 (with unit)"),
    (0x20, "string"),
    (0x21, "bool"),
    (0x44, "timestamp"),
    (0x8_000c, "complex64"),
    (0x10_000d, "complex128"),
    (0xffff_ffff, "DAQmx raw"),
];

record! {
    pub struct TdmsLeadIn {
        tag: ascii[4] "Tag",
        toc: u32 "ToC mask" .flags(TDMS_TOC),
        version: u32 "Version",
        next_segment: u64 "Next segment offset" .hex().desc("Relative to the end of the lead-in"),
        raw_offset: u64 "Raw data offset" .hex().desc("Relative to the end of the lead-in"),
    }
}

async fn tdms(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut segments = 0u32;
    let mut objects = Vec::new();
    let mut version = 0u32;
    while pos.saturating_add(TdmsLeadIn::SIZE) <= file.len {
        cx.progress_in(file, file.offset.saturating_add(pos));
        // The lead-in itself is always little endian.
        let lead: TdmsLeadIn = read_record(&cx, file.sub(pos, TdmsLeadIn::SIZE), LE).await?;
        if !lead.tag.starts_with("TDS") {
            cx.diag(Diagnostic::malformed("expected a TDMS segment lead-in").at(file.sub(pos, 4)));
            break;
        }
        version = lead.version;
        let body_at = pos.saturating_add(TdmsLeadIn::SIZE);
        let incomplete = lead.next_segment == u64::MAX;
        let len = if incomplete {
            file.len.saturating_sub(body_at)
        } else {
            lead.next_segment
        };
        let endian = if lead.toc & 0x40 != 0 { BE } else { LE };
        let meta = file.sub(body_at, lead.raw_offset.min(len));
        if lead.toc & 0x2 != 0 && objects.len() < 64 {
            let names = tdms_object_names(&cx, meta, endian)
                .await
                .unwrap_or_default();
            objects.extend(names);
        }
        let span = file.sub(pos, TdmsLeadIn::SIZE.saturating_add(len));
        let mut node = Node::new(format!("Segment {segments}"))
            .span(span)
            .summary(format!(
                "{} bytes of metadata, {} bytes of raw data",
                meta.len,
                len.saturating_sub(lead.raw_offset)
            ))
            .lazy(
                tdms_segment,
                (
                    file.sub(pos, TdmsLeadIn::SIZE),
                    meta,
                    file.sub(
                        body_at.saturating_add(lead.raw_offset),
                        len.saturating_sub(lead.raw_offset),
                    ),
                    lead.toc,
                ),
            );
        if incomplete {
            node = node.diag(Diagnostic::warning(
                "segment was not completed (next segment offset is -1)",
            ));
        }
        cx.push(node).await;
        segments = segments.saturating_add(1);
        pos = body_at.saturating_add(len.max(1));
    }
    let channels: Vec<&String> = objects
        .iter()
        .filter(|o| o.matches("'/'").count() == 2)
        .collect();
    cx.annotate(format!(
        "TDMS {}, {segments} segment(s){}",
        if version == 4713 { "2.0" } else { "1.0" },
        if channels.is_empty() {
            String::new()
        } else {
            format!(
                ", channels {}",
                preview(
                    &channels
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    100
                )
            )
        }
    ));
    Ok(())
}

async fn tdms_string(cur: &mut Cursor<'_>) -> Result<String> {
    let len = cur.u32().await?;
    if u64::from(len) > cur.remaining() {
        return Err(Diagnostic::malformed(format!("string of {len} bytes")));
    }
    Ok(String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned())
}

async fn tdms_object_names(cx: &Cx, meta: Span, endian: Endian) -> Result<Vec<String>> {
    let mut cur = Cursor::new(cx, meta, endian);
    let count = cur.u32().await?;
    let mut out = Vec::new();
    for _ in 0..count.min(64) {
        let path = tdms_string(&mut cur).await?;
        tdms_skip_index(&mut cur).await?;
        let props = cur.u32().await?;
        for _ in 0..props {
            tdms_string(&mut cur).await?;
            let t = cur.u32().await?;
            tdms_value(&mut cur, t).await?;
        }
        out.push(path);
    }
    Ok(out)
}

/// Skips a raw data index; returns a description of it.
async fn tdms_skip_index(cur: &mut Cursor<'_>) -> Result<String> {
    let len = cur.u32().await?;
    Ok(match len {
        0xffff_ffff => "no raw data".to_owned(),
        0 => "same index as the previous segment".to_owned(),
        0x6912_0000..=0x6913_ffff => {
            // DAQmx format changing / digital line scaler.
            let t = cur.u32().await?;
            let dims = cur.u32().await?;
            let n = cur.u64().await?;
            let scalers = cur.u32().await?;
            cur.skip(u64::from(scalers).saturating_mul(17));
            let widths = cur.u32().await?;
            cur.skip(u64::from(widths).saturating_mul(4));
            format!("DAQmx {t:#x}, {dims} dim(s), {n} value(s)")
        }
        _ => {
            let at = cur.pos();
            let t = cur.u32().await?;
            let dims = cur.u32().await?;
            let n = cur.u64().await?;
            let mut s = format!(
                "{} × {n}{}",
                lookup(TDMS_TYPES, t.into()).unwrap_or("?"),
                if dims == 1 {
                    String::new()
                } else {
                    format!(" ({dims} dims)")
                }
            );
            if t == 0x20 {
                let size = cur.u64().await?;
                s = format!("{s}, {size} bytes");
            }
            cur.seek(
                at.saturating_add(u64::from(len).saturating_sub(4))
                    .max(cur.pos()),
            );
            s
        }
    })
}

async fn tdms_value(cur: &mut Cursor<'_>, t: u32) -> Result<Value> {
    Ok(match t {
        1 => int(i64::from(cur.u8().await?.cast_signed())),
        2 => int(i64::from(cur.u16().await?.cast_signed())),
        3 => int(i64::from(cur.u32().await?.cast_signed())),
        4 => int(cur.u64().await?.cast_signed()),
        5 => uint(cur.u8().await?.into()),
        6 => uint(cur.u16().await?.into()),
        7 => uint(cur.u32().await?.into()),
        8 => uint(cur.u64().await?),
        9 | 0x19 => float32(cur.int::<f32>().await?),
        10 | 0x1a => float(cur.int::<f64>().await?),
        0x20 => text(tdms_string(cur).await?),
        0x21 => Value::Bool(cur.u8().await? != 0),
        0x44 => {
            let _fraction = cur.u64().await?;
            let secs = cur.u64().await?.cast_signed();
            // Seconds since 1904-01-01 UTC.
            Value::Timestamp {
                unix_seconds: secs.saturating_sub(crate::text::MAC_EPOCH),
            }
        }
        0x8_000c => {
            cur.skip(8);
            text("complex64")
        }
        0x10_000d => {
            cur.skip(16);
            text("complex128")
        }
        _ => return Err(Diagnostic::unsupported(format!("TDMS data type {t:#x}"))),
    })
}

async fn tdms_segment(cx: Cx, (lead, meta, raw, toc): (Span, Span, Span, u32)) -> Result<()> {
    cx.emit(TdmsLeadIn::node("Lead-in", lead, LE));
    let endian = if toc & 0x40 != 0 { BE } else { LE };
    if toc & 0x2 != 0 && meta.len > 0 {
        cx.emit(
            Node::new("Metadata")
                .span(meta)
                .lazy(tdms_meta, (meta, endian)),
        );
    }
    if raw.len > 0 {
        cx.emit(Node::new("Raw data").span(raw).summary(if toc & 0x20 != 0 {
            "interleaved"
        } else {
            "contiguous"
        }));
    }
    Ok(())
}

async fn tdms_meta(cx: Cx, (meta, endian): (Span, Endian)) -> Result<()> {
    let mut cur = Cursor::new(&cx, meta, endian);
    let count = cur.u32().await?;
    cx.emit(
        Node::new("Object count")
            .span(meta.sub(0, 4))
            .value(uint(count.into())),
    );
    for _ in 0..count {
        let start = cur.pos();
        let path = tdms_string(&mut cur).await?;
        let index = tdms_skip_index(&mut cur).await?;
        let props_at = cur.pos();
        let props = cur.u32().await?;
        let mut list = Vec::new();
        for _ in 0..props {
            let ps = cur.pos();
            let name = tdms_string(&mut cur).await?;
            let t = cur.u32().await?;
            let v = tdms_value(&mut cur, t).await?;
            list.push((name, v, t, cur.since(ps)));
        }
        let _ = props_at;
        cx.push(
            Node::new(if path == "/" {
                "/ (file)".to_owned()
            } else {
                path
            })
            .span(cur.since(start))
            .summary(index)
            .lazy(tdms_props, list),
        )
        .await;
    }
    Ok(())
}

async fn tdms_props(cx: Cx, list: Vec<(String, Value, u32, Span)>) -> Result<()> {
    for (name, v, t, span) in list {
        cx.push(
            Node::new(name)
                .span(span)
                .value(v)
                .desc(lookup(TDMS_TYPES, t.into()).unwrap_or("?")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MNIST-style IDX arrays

fn idx_size(kind: u8) -> u64 {
    match kind {
        0x08 | 0x09 => 1,
        0x0b => 2,
        0x0c | 0x0d => 4,
        0x0e => 8,
        _ => 0,
    }
}

fn idx_probe(h: &Head<'_>) -> bool {
    let (Some(&kind), Some(&dims)) = (h.data.get(2), h.data.get(3)) else {
        return false;
    };
    if !h.at(0, b"\0\0") || idx_size(kind) == 0 || dims == 0 || dims > 8 {
        return false;
    }
    let mut total = idx_size(kind);
    for i in 0..usize::from(dims) {
        let Some(d) = u32_be(h.data, 4usize.saturating_add(i.saturating_mul(4))) else {
            return false;
        };
        total = total.saturating_mul(d.into());
    }
    total.saturating_add(4u64.saturating_add(4u64.saturating_mul(dims.into()))) == h.len
}

declare_format!(pub IDX = "idx", "IDX array (MNIST)", ["idx", "idx1-ubyte", "idx3-ubyte"], "application/x-idx",
    Probe::Custom(idx_probe), idx);

const IDX_TYPES: EnumTable = &[
    (0x08, "uint8"),
    (0x09, "int8"),
    (0x0b, "int16"),
    (0x0c, "int32"),
    (0x0d, "float32"),
    (0x0e, "float64"),
];

async fn idx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 36)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u16("Zero").emit()?;
    let kind = f.u8("Data type").enumeration(IDX_TYPES).emit()?;
    let ndims = f.u8("Dimensions").emit()?;
    let mut dims = Vec::new();
    for _ in 0..ndims.min(8) {
        dims.push(u64::from(f.u32("Size").emit()?));
    }
    let header = 4u64.saturating_add(4u64.saturating_mul(ndims.into()));
    let item: u64 = dims
        .iter()
        .skip(1)
        .product::<u64>()
        .saturating_mul(idx_size(kind));
    let count = dims.first().copied().unwrap_or(0);
    cx.emit(
        Node::new("Items")
            .span(file.tail(header))
            .value(uint(count))
            .lazy(
                idx_items,
                (file.tail(header), count, item, kind, dims.clone()),
            ),
    );
    let shape: Vec<String> = dims.iter().map(u64::to_string).collect();
    cx.annotate(format!(
        "IDX {} array, shape {}",
        lookup(IDX_TYPES, kind.into()).unwrap_or("?"),
        shape.join("×")
    ));
    Ok(())
}

async fn idx_items(
    cx: Cx,
    (span, count, item, kind, dims): (Span, u64, u64, u8, Vec<u64>),
) -> Result<()> {
    cx.set_count(Count::Exact(count));
    let size = idx_size(kind);
    for i in 0..count {
        let s = span.sub(i.saturating_mul(item), item);
        let b = cx.read_avail(s.sub(0, size.saturating_mul(12))).await?;
        let vals: Vec<String> = b
            .chunks(to_usize(size).max(1))
            .filter(|c| to_u64(c.len()) == size)
            .map(|c| match kind {
                0x08 => c.first().copied().unwrap_or(0).to_string(),
                0x09 => c.first().copied().unwrap_or(0).cast_signed().to_string(),
                0x0b => crate::bytes::u16_be(c, 0)
                    .unwrap_or(0)
                    .cast_signed()
                    .to_string(),
                0x0c => crate::bytes::i32_be(c, 0).unwrap_or(0).to_string(),
                0x0d => f32::from_bits(u32_be(c, 0).unwrap_or(0)).to_string(),
                _ => f64::from_bits(crate::bytes::u64_be(c, 0).unwrap_or(0)).to_string(),
            })
            .collect();
        let node = Node::new(format!("Item {i}")).span(s);
        cx.push(if dims.len() == 1 {
            node.value(number(vals.first().map_or("", String::as_str)))
        } else {
            node.summary(format!(
                "{}{}",
                vals.join(" "),
                if item > size.saturating_mul(12) {
                    " …"
                } else {
                    ""
                }
            ))
        })
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Blackrock Microsystems NEV and NSx

declare_format!(pub NEV = "nev", "Blackrock neural events (NEV)", ["nev"], "application/x-blackrock-nev",
    Probe::Magic(&[(0, b"NEURALEV"), (0, b"BREVENTS")]), nev);
declare_format!(pub NSX = "nsx", "Blackrock continuous data (NSx)", ["ns1", "ns2", "ns3", "ns4", "ns5", "ns6", "nsx"], "application/x-blackrock-nsx",
    Probe::Magic(&[(0, b"NEURALCD"), (0, b"NEURALSG"), (0, b"BRSMPGRP")]), nsx);

record! {
    pub struct NevHeader {
        magic: ascii[8] "File type ID",
        major: u8 "File spec major",
        minor: u8 "File spec minor",
        flags: u16 "Additional flags" .hex(),
        header_bytes: u32 "Bytes in headers",
        packet_bytes: u32 "Bytes in data packets",
        ts_resolution: u32 "Time resolution of timestamps (Hz)",
        sample_resolution: u32 "Time resolution of samples (Hz)",
        origin: bytes[16] "Time origin (SYSTEMTIME)",
        application: ascii[32] "Application",
        comment: ascii[256] "Comment",
        extended: u32 "Number of extended headers",
    }
}

async fn nev(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: NevHeader = read_record(&cx, file.sub(0, NevHeader::SIZE), LE).await?;
    cx.emit(
        NevHeader::node("Basic header", file.sub(0, NevHeader::SIZE), LE)
            .summary(systemtime(&h.origin)),
    );
    let ext = file.sub(NevHeader::SIZE, u64::from(h.extended).saturating_mul(32));
    cx.emit(
        Node::new("Extended headers")
            .span(ext)
            .value(uint(h.extended.into()))
            .lazy(nev_extended, ext),
    );
    let data = file.tail(h.header_bytes.into());
    let packet = u64::from(h.packet_bytes);
    if packet >= 6 {
        cx.emit(
            Node::new("Data packets")
                .span(data)
                .summary(format!(
                    "{} × {packet} bytes",
                    data.len.checked_div(packet).unwrap_or(0)
                ))
                .lazy(nev_packets, (data, packet, h.ts_resolution)),
        );
    }
    cx.annotate(format!(
        "Blackrock NEV {}.{}, {}, recorded {}, {} packet(s)",
        h.major,
        h.minor,
        h.application.trim_end_matches('\0'),
        systemtime(&h.origin),
        data.len.checked_div(packet).unwrap_or(0)
    ));
    Ok(())
}

async fn nev_extended(cx: Cx, span: Span) -> Result<()> {
    let mut at = 0u64;
    while at.saturating_add(32) <= span.len {
        let s = span.sub(at, 32);
        let b = cx.read(s).await?;
        let id = field_text(b.get(..8).unwrap_or_default());
        let body = b.get(8..).unwrap_or_default();
        let summary = match id.as_str() {
            "NEUEVWAV" => format!(
                "electrode {}, bank {}, pin {}",
                u16_le(body, 0).unwrap_or(0),
                char::from(
                    body.get(2)
                        .copied()
                        .unwrap_or(b'?')
                        .saturating_add(b'A')
                        .saturating_sub(1)
                ),
                body.get(3).copied().unwrap_or(0)
            ),
            "NEUEVLBL" => format!(
                "electrode {}: {}",
                u16_le(body, 0).unwrap_or(0),
                field_text(body.get(2..18).unwrap_or_default())
            ),
            "DIGLABEL" => field_text(body.get(..16).unwrap_or_default()),
            "ARRAYNME" | "MAPFILE" | "ECOMMENT" | "CCOMMENT" => field_text(body),
            _ => String::new(),
        };
        cx.push(summarize(Node::new(id).span(s), summary)).await;
        at = at.saturating_add(32);
    }
    Ok(())
}

async fn nev_packets(cx: Cx, (data, packet, resolution): (Span, u64, u32)) -> Result<()> {
    let count = data.len.checked_div(packet).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let s = data.sub(i.saturating_mul(packet), packet);
        let b = cx.read_avail(s.sub(0, 8)).await?;
        let ts = u32_le(&b, 0).unwrap_or(0);
        let id = u16_le(&b, 4).unwrap_or(0);
        let kind = match id {
            0 => "digital/serial event".to_owned(),
            0xffff => "configuration".to_owned(),
            0xfffe => "comment".to_owned(),
            0xfffd => "video sync".to_owned(),
            0xfffc => "tracking".to_owned(),
            0xfffb => "button trigger".to_owned(),
            e => format!("spike on electrode {e}"),
        };
        let secs = f64::from(ts) / f64::from(resolution.max(1));
        cx.push(
            Node::new(format!("Packet {i}"))
                .span(s)
                .value(uint(ts.into()))
                .summary(format!("{secs:.4} s, {kind}")),
        )
        .await;
    }
    Ok(())
}

async fn nsx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 8)).await?;
    if magic == b"NEURALSG" {
        let b = cx.block(file.sub(0, 32)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        f.ascii("File type ID", 8).emit()?;
        let label = f.ascii("Label", 16).emit()?;
        let period = f.u32("Period (1/30 kHz)").emit()?;
        let count = f.u32("Channel count").emit()?;
        cx.emit(Node::new("Channel IDs").span(file.sub(32, u64::from(count).saturating_mul(4))));
        cx.emit(
            Node::new("Data")
                .span(file.tail(32u64.saturating_add(u64::from(count).saturating_mul(4)))),
        );
        cx.annotate(format!(
            "Blackrock NSx 2.1 {}, {count} channel(s) at {} Hz",
            label.trim_end_matches('\0'),
            30000u32.checked_div(period).unwrap_or(0)
        ));
        return Ok(());
    }
    let b = cx.block(file.sub(0, 314)).await?;
    let mut f = Fields::emitting(&cx, &b, LE);
    f.ascii("File type ID", 8).emit()?;
    let major = f.u8("File spec major").emit()?;
    let minor = f.u8("File spec minor").emit()?;
    let header_bytes = f.u32("Bytes in headers").emit()?;
    let label = f.ascii("Label", 16).emit()?;
    f.ascii("Comment", 256).emit()?;
    let period = f
        .u32("Period")
        .desc("Sample period in units of the time resolution")
        .emit()?;
    let resolution = f.u32("Time resolution (Hz)").emit()?;
    f.bytes("Time origin (SYSTEMTIME)", 16)
        .with(|v, n| n.summary(systemtime(v)))
        .emit()?;
    let count = f.u32("Channel count").emit()?;
    let ext = file.sub(314, u64::from(count).saturating_mul(66));
    cx.emit(
        Node::new("Channel headers")
            .span(ext)
            .value(uint(count.into()))
            .lazy(nsx_channels, ext),
    );
    cx.emit(
        Node::new("Data packets")
            .span(file.tail(header_bytes.into()))
            .lazy(
                nsx_packets,
                (file.tail(header_bytes.into()), u64::from(count), major),
            ),
    );
    let rate = resolution.checked_div(period).unwrap_or(0);
    cx.annotate(format!(
        "Blackrock NSx {major}.{minor} {}, {count} channel(s) at {rate} Hz",
        label.trim_end_matches('\0')
    ));
    Ok(())
}

record! {
    pub struct NsxChannel {
        kind: ascii[2] "Type",
        electrode: u16 "Electrode ID",
        label: ascii[16] "Label",
        front_end: u8 "Front-end ID",
        pin: u8 "Front-end pin",
        min_digital: i16 "Min digital value",
        max_digital: i16 "Max digital value",
        min_analog: i16 "Min analog value",
        max_analog: i16 "Max analog value",
        units: ascii[16] "Units",
        high_corner: u32 "High-pass corner (mHz)",
        high_order: u32 "High-pass order",
        high_type: u16 "High-pass type",
        low_corner: u32 "Low-pass corner (mHz)",
        low_order: u32 "Low-pass order",
        low_type: u16 "Low-pass type",
    }
}

async fn nsx_channels(cx: Cx, span: Span) -> Result<()> {
    let mut at = 0u64;
    while at.saturating_add(NsxChannel::SIZE) <= span.len {
        let s = span.sub(at, NsxChannel::SIZE);
        let c: NsxChannel = read_record(&cx, s, LE).await?;
        cx.push(
            NsxChannel::node(c.label.trim_end_matches('\0').to_owned(), s, LE).summary(format!(
                "electrode {}, {}–{} {}",
                c.electrode,
                c.min_analog,
                c.max_analog,
                c.units.trim_end_matches('\0')
            )),
        )
        .await;
        at = at.saturating_add(NsxChannel::SIZE);
    }
    Ok(())
}

async fn nsx_packets(cx: Cx, (data, channels, major): (Span, u64, u8)) -> Result<()> {
    let mut cur = Cursor::new(&cx, data, LE);
    let mut i = 0u32;
    while cur.remaining() >= 9 {
        cx.progress_in(data, data.offset.saturating_add(cur.pos()));
        let start = cur.pos();
        let header = cur.u8().await?;
        if header != 1 {
            cx.diag(
                Diagnostic::malformed(format!("data packet header {header:#x}"))
                    .at(cur.since(start)),
            );
            break;
        }
        let ts = if major >= 3 {
            cur.u64().await?
        } else {
            cur.u32().await?.into()
        };
        let points = cur.u32().await?;
        cur.skip(u64::from(points).saturating_mul(channels).saturating_mul(2));
        cx.push(
            Node::new(format!("Packet {i}"))
                .span(cur.since(start))
                .value(uint(ts))
                .summary(format!("{points} sample(s) × {channels} channel(s)")),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Plexon PLX

declare_format!(pub PLEXON = "plexon-plx", "Plexon PLX recording", ["plx"], "application/x-plexon-plx",
    Probe::Custom(|h| h.at(0, b"PLEX") && u32_le(h.data, 4).is_some_and(|v| (100..=200).contains(&v))), plexon);

async fn plexon(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 256)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let version = f.u32("Version").emit()?;
    let comment = f.ascii("Comment", 128).emit()?;
    let ad_freq = f.u32("A/D frequency (Hz)").emit()?;
    let dsp = f.u32("DSP channels").emit()?;
    let events = f.u32("Event channels").emit()?;
    let slow = f.u32("Slow channels").emit()?;
    f.u32("Points per waveform").emit()?;
    f.u32("Points before threshold").emit()?;
    let mut date = Vec::new();
    for name in ["Year", "Month", "Day", "Hour", "Minute", "Second"] {
        date.push(f.u32(name).emit()?);
    }
    f.u32("Fast read").emit()?;
    f.u32("Waveform frequency (Hz)").emit()?;
    f.f64("Last timestamp").emit()?;
    let header = 7504u64;
    cx.emit(
        Node::new("Counts")
            .span(file.sub(256, header.saturating_sub(256)))
            .desc("Timestamp, waveform and event counts per channel"),
    );
    let dsp_span = file.sub(header, u64::from(dsp).saturating_mul(1020));
    let ev_span = file.sub(
        dsp_span.end().saturating_sub(file.offset),
        u64::from(events).saturating_mul(296),
    );
    let slow_span = file.sub(
        ev_span.end().saturating_sub(file.offset),
        u64::from(slow).saturating_mul(296),
    );
    cx.emit(
        Node::new("Spike channels")
            .span(dsp_span)
            .value(uint(dsp.into()))
            .lazy(plx_channels, (dsp_span, 1020u64)),
    );
    cx.emit(
        Node::new("Event channels")
            .span(ev_span)
            .value(uint(events.into()))
            .lazy(plx_channels, (ev_span, 296u64)),
    );
    cx.emit(
        Node::new("Slow (continuous) channels")
            .span(slow_span)
            .value(uint(slow.into()))
            .lazy(plx_channels, (slow_span, 296u64)),
    );
    let data = file.tail(slow_span.end().saturating_sub(file.offset));
    cx.emit(Node::new("Data blocks").span(data).lazy(plx_blocks, data));
    let d = |i: usize| date.get(i).copied().unwrap_or(0);
    cx.annotate(format!(
        "Plexon PLX v{version}, {dsp} spike / {events} event / {slow} slow channel(s), {ad_freq} Hz, {:04}-{:02}-{:02} {:02}:{:02}{}",
        d(0),
        d(1),
        d(2),
        d(3),
        d(4),
        if comment.trim_end_matches('\0').is_empty() { String::new() } else { format!(", {}", comment.trim_end_matches('\0')) }
    ));
    Ok(())
}

async fn plx_channels(cx: Cx, (span, size): (Span, u64)) -> Result<()> {
    let mut at = 0u64;
    while at.saturating_add(size) <= span.len {
        let s = span.sub(at, size);
        let b = cx.read(s.sub(0, 40)).await?;
        let name = field_text(b.get(..32).unwrap_or_default());
        let channel = u32_le(&b, 32).unwrap_or(0);
        cx.push(
            Node::new(name)
                .span(s)
                .value(uint(channel.into()))
                .desc("Channel number"),
        )
        .await;
        at = at.saturating_add(size);
    }
    Ok(())
}

const PLX_BLOCKS: EnumTable = &[(1, "spike"), (4, "event"), (5, "continuous")];

async fn plx_blocks(cx: Cx, data: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, data, LE);
    while cur.remaining() >= 16 {
        cx.progress_in(data, data.offset.saturating_add(cur.pos()));
        let start = cur.pos();
        let kind = cur.u16().await?;
        let upper = cur.u16().await?;
        let ts = cur.u32().await?;
        let channel = cur.u16().await?;
        let unit = cur.u16().await?;
        let waveforms = cur.u16().await?;
        let words = cur.u16().await?;
        cur.skip(
            u64::from(waveforms)
                .saturating_mul(words.into())
                .saturating_mul(2),
        );
        let timestamp = (u64::from(upper) << 32) | u64::from(ts);
        cx.push(
            Node::new(lookup(PLX_BLOCKS, kind.into()).unwrap_or("block"))
                .span(cur.since(start))
                .value(uint(timestamp))
                .summary(format!(
                    "channel {channel}, unit {unit}, {waveforms} × {words} words"
                )),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BrainVision header/marker files (INI-style)

declare_format!(pub BRAINVISION_HEADER = "brainvision-vhdr", "BrainVision header", ["vhdr"], "text/x-brainvision-header",
    Probe::Custom(|h| h.starts_with(b"Brain Vision Data Exchange Header File") || h.starts_with(b"BrainVision Data Exchange Header File")), brainvision);
declare_format!(pub BRAINVISION_MARKERS = "brainvision-vmrk", "BrainVision markers", ["vmrk"], "text/x-brainvision-markers",
    Probe::Custom(|h| h.starts_with(b"Brain Vision Data Exchange Marker File") || h.starts_with(b"BrainVision Data Exchange Marker File")), brainvision);

async fn brainvision(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    // The open section: name, start, and its key/value entries.
    type Section = (String, u64, Vec<(String, String, Span)>);
    let mut section: Option<Section> = None;
    let mut first = String::new();
    let mut summary: Vec<(String, String)> = Vec::new();
    loop {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        let next = lines.next().await?;
        let starts = next.as_ref().is_none_or(|l| l.bytes.starts_with(b"["));
        if starts && let Some((name, start, entries)) = section.take() {
            let end = next.as_ref().map_or(lines.pos(), |l| l.pos);
            let n = entries.len();
            cx.push(
                Node::new(format!("[{name}]"))
                    .span(file.sub(start, end.saturating_sub(start)))
                    .summary(format!("{n} entr(ies)"))
                    .lazy(ini_entries, entries),
            )
            .await;
        }
        let Some(line) = next else { break };
        let t = line.text();
        if line.pos == 0 {
            first.clone_from(&t);
            cx.emit(
                Node::new("Identification")
                    .span(line.content())
                    .value(text(t)),
            );
            continue;
        }
        if starts {
            section = Some((
                t.trim().trim_matches(['[', ']']).to_owned(),
                line.pos,
                Vec::new(),
            ));
        } else if let Some((_, _, entries)) = section.as_mut()
            && let Some((k, v)) = t.split_once('=')
            && !t.starts_with(';')
            && entries.len() < 100_000
        {
            if [
                "DataFile",
                "NumberOfChannels",
                "SamplingInterval",
                "DataFormat",
                "BinaryFormat",
            ]
            .contains(&k.trim())
            {
                summary.push((k.trim().to_owned(), v.trim().to_owned()));
            }
            entries.push((k.trim().to_owned(), v.trim().to_owned(), line.content()));
        }
    }
    let get = |k: &str| {
        summary
            .iter()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.as_str())
    };
    let mut note = preview(&first, 60);
    if let Some(n) = get("NumberOfChannels") {
        note = format!("{note}; {n} channel(s)");
    }
    if let Some(si) = get("SamplingInterval")
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
    {
        note = format!("{note} at {:.0} Hz", 1e6 / si);
    }
    if let Some(d) = get("DataFile") {
        note = format!("{note}, data in {d}");
    }
    cx.annotate(note);
    Ok(())
}

async fn ini_entries(cx: Cx, entries: Vec<(String, String, Span)>) -> Result<()> {
    for (k, v, span) in entries {
        // Marker and channel entries pack fields with commas.
        let node = Node::new(k).span(span).value(text(v.clone()));
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Neuralynx (16 KiB text header + fixed records)

declare_format!(pub NEURALYNX = "neuralynx", "Neuralynx recording", ["ncs", "nse", "ntt", "nev", "nvt"], "application/x-neuralynx",
    Probe::Custom(|h| h.starts_with(b"######## Neuralynx") || (h.starts_with(b"########") && h.len >= 16384 && contains(h.data.get(..2048).unwrap_or_default(), b"\n-FileType"))), neuralynx);

async fn neuralynx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = file.sub(0, 16384);
    let raw = cx.read_avail(header).await?;
    let text_len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let header_text = String::from_utf8_lossy(raw.get(..text_len).unwrap_or_default()).into_owned();
    let get = |key: &str| {
        header_text.lines().find_map(|l| {
            l.trim()
                .strip_prefix('-')
                .and_then(|r| r.strip_prefix(key))
                .filter(|r| r.starts_with([' ', '\t']))
                .map(|r| r.trim().to_owned())
        })
    };
    let kind = get("FileType").unwrap_or_default();
    cx.emit(
        Node::new("Header")
            .span(header)
            .lazy(neuralynx_header, header.sub(0, to_u64(text_len))),
    );
    let size: u64 = match kind.as_str() {
        "CSC" => 1044,
        "Spike" => 112,
        "Event" => 184,
        "Video" => 1828,
        _ => 0,
    };
    let records = file.tail(16384);
    let count = records.len.checked_div(size).unwrap_or(0);
    let mut node = Node::new("Records")
        .span(records)
        .summary(format!("{count} × {size} bytes"));
    if kind == "CSC" {
        node = node.lazy(ncs_records, records);
    }
    cx.emit(node);
    let rate = get("SamplingFrequency").unwrap_or_default();
    let name = get("AcqEntName").unwrap_or_default();
    cx.annotate(format!(
        "Neuralynx {} file{}, {count} record(s){}",
        if kind.is_empty() {
            "data"
        } else {
            kind.as_str()
        },
        if name.is_empty() {
            String::new()
        } else {
            format!(" ({name})")
        },
        if rate.is_empty() {
            String::new()
        } else {
            format!(" at {rate} Hz")
        }
    ));
    Ok(())
}

async fn neuralynx_header(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim();
        if let Some(rest) = t.strip_prefix('-') {
            let (k, v) = rest.split_once([' ', '\t']).unwrap_or((rest, ""));
            cx.push(
                Node::new(k.to_owned())
                    .span(line.content())
                    .value(number(v.trim())),
            )
            .await;
        } else if !t.is_empty() {
            cx.push(Node::new("Comment").span(line.content()).value(text(t)))
                .await;
        }
    }
    Ok(())
}

record! {
    pub struct NcsRecord {
        timestamp: u64 "Timestamp (µs)",
        channel: u32 "Channel",
        rate: u32 "Sample frequency (Hz)",
        valid: u32 "Valid samples",
    }
}

async fn ncs_records(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / 1044;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let s = span.sub(i.saturating_mul(1044), 1044);
        let r: NcsRecord = read_record(&cx, s.sub(0, NcsRecord::SIZE), LE).await?;
        cx.push(
            Node::new(format!("Record {i}"))
                .span(s)
                .value(uint(r.timestamp))
                .summary(format!(
                    "channel {}, {} valid sample(s) at {} Hz",
                    r.channel, r.valid, r.rate
                ))
                .lazy(ncs_record, s),
        )
        .await;
    }
    Ok(())
}

async fn ncs_record(cx: Cx, s: Span) -> Result<()> {
    cx.emit(NcsRecord::node("Header", s.sub(0, NcsRecord::SIZE), LE));
    let b = cx.read_avail(s.sub(NcsRecord::SIZE, 16)).await?;
    let shown: Vec<String> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| i16::from_le_bytes(*c).to_string())
        .collect();
    cx.emit(
        Node::new("Samples")
            .span(s.tail(NcsRecord::SIZE))
            .summary(format!("512 × int16: {}, …", shown.join(", "))),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::util::pace::run_all;

    #[test]
    fn fcs_pairs_handle_escaped_delimiters() {
        let span = Span::new(crate::span::SourceId(0), 0, 100);
        let pairs = run_all(FcsPairs::new(b"/$PAR/2/$P1N/FS//C/", span));
        let kv: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v, _)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(kv, vec![("$PAR", "2"), ("$P1N", "FS/C")]);
    }

    #[test]
    fn gdf_times() {
        assert_eq!(
            gdf_time(719_529u64 << 32),
            Value::Timestamp { unix_seconds: 0 }
        );
        assert_eq!(read_uint(&[1, 2], Endian::Little), 0x201);
        assert!(
            crate::formats::util::lines::head_lines(
                &Head {
                    data: b"a\nb",
                    tail: b"",
                    len: 3,
                    len_known: true,
                },
                2
            )
            .len()
                == 2
        );
    }
}
