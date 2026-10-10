//! MPEG-2 transport streams (ISO 13818-1): 188-byte packets, plus the
//! 192-byte BDAV/M2TS variant (4-byte timecode prefix) and 204-byte packets
//! with Reed-Solomon parity.
//!
//! The first packets are scanned once: PSI and DVB SI sections are
//! reassembled across packets (spans map back to the packets they came
//! from), giving programs, services and streams, and the first PES packet
//! of each stream gives its codec details (H.264/HEVC parameter sets, MPEG
//! video sequence headers, audio frame headers). The duration comes from
//! the PCR (or PTS) at both ends. Packets are listed in pages, each
//! decoded on expansion; a per-PID view counts packets and continuity
//! errors over the whole stream.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::vidutil::{self, NalCodec, ParamSets, enumerated, flag_node, hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value};

use super::si::{self, STREAM_TYPES};
use super::{pes_header, pes_summary, pes_times, seconds_90k};

pub static FORMAT: Format = Format {
    name: "mpegts",
    title: "MPEG transport stream",
    extensions: &["ts", "tsv", "tsa", "mpegts", "trp"],
    mime: "video/mp2t",
    probe: Probe::Custom(|h| matches!(layout(h), Some(l) if l.stride != 192)),
    dissect: crate::expander!(dissect: Input),
};

pub static M2TS: Format = Format {
    name: "m2ts",
    title: "BDAV MPEG-2 transport stream",
    extensions: &["m2ts", "mts", "m2t"],
    mime: "video/mp2t",
    probe: Probe::Custom(|h| matches!(layout(h), Some(l) if l.stride == 192)),
    dissect: crate::expander!(dissect: Input),
};

/// Packet framing: stride and where the sync byte sits in each packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    stride: u64,
    /// Bytes before the 188-byte packet (4 for M2TS).
    prefix: u64,
}

fn layout(h: &Head<'_>) -> Option<Layout> {
    for (stride, prefix) in [(188usize, 0usize), (192, 4), (204, 0)] {
        let available = h
            .data
            .len()
            .saturating_sub(prefix)
            .checked_div(stride)
            .unwrap_or(0);
        let need = available.min(6);
        if need < 2 {
            continue;
        }
        let ok = (0..need).all(|k| {
            k.checked_mul(stride)
                .and_then(|o| o.checked_add(prefix))
                .and_then(|o| h.data.get(o))
                == Some(&0x47)
        });
        if ok {
            return Some(Layout {
                stride: to_u64(stride),
                prefix: to_u64(prefix),
            });
        }
    }
    None
}

const ADAPTATION: EnumTable = &[
    (1, "payload only"),
    (2, "adaptation field only"),
    (3, "adaptation field and payload"),
];

const SCRAMBLING: EnumTable = &[
    (0, "not scrambled"),
    (1, "reserved"),
    (2, "scrambled with even key"),
    (3, "scrambled with odd key"),
];

/// A section reassembled from one or more packets.
#[derive(Clone, Debug)]
struct Section {
    pid: u16,
    table: u8,
    /// Exact bytes (a pieces source when the section spans packets).
    span: Span,
    summary: Option<String>,
    crc_ok: Option<bool>,
}

#[derive(Clone, Debug, Default)]
struct Stream {
    pid: u16,
    kind: u8,
    /// The stream's entry in the PMT.
    span: Option<Span>,
    descriptors: Vec<(u8, Vec<u8>)>,
    /// Codec details from the first PES packet.
    detail: Option<String>,
    first_pts: Option<u64>,
}

impl Stream {
    fn has(&self, tag: u8) -> bool {
        self.descriptors.iter().any(|(t, _)| *t == tag)
    }

    fn registration(&self) -> Option<[u8; 4]> {
        registration(&self.descriptors)
    }

    fn language(&self) -> Option<String> {
        let (_, b) = self.descriptors.iter().find(|(t, _)| *t == 0x0a)?;
        let l = b.get(..3)?;
        Some(String::from_utf8_lossy(l).into_owned())
    }

    /// The codec, from the stream type and descriptors.
    fn codec(&self, program: Option<[u8; 4]>, m2ts: bool) -> String {
        let hdmv = m2ts || program == Some(*b"HDMV");
        let reg = self
            .registration()
            .map(|r| String::from_utf8_lossy(&r).into_owned());
        let reg = reg.as_deref();
        let name = match self.kind {
            0x06 => {
                if self.has(0x6a) || reg == Some("AC-3") {
                    "AC-3"
                } else if self.has(0x7a) || reg == Some("EAC3") {
                    "E-AC-3"
                } else if self.has(0x7b) || reg.is_some_and(|r| r.starts_with("DTS")) {
                    "DTS"
                } else if self.has(0x7c) {
                    "AAC"
                } else if self.has(0x56) {
                    "teletext"
                } else if self.has(0x59) {
                    "DVB subtitles"
                } else if self.has(0x45) {
                    "VBI data"
                } else {
                    match reg {
                        Some("Opus") => "Opus",
                        Some("HEVC") => "HEVC",
                        Some("AV01") => "AV1",
                        Some("VC-1") => "VC-1",
                        Some("KLVA") => "KLV metadata",
                        Some("ID3 ") => "ID3 metadata",
                        Some("VANC") => "SMPTE 2038 ancillary data",
                        Some("BSSD") => "SMPTE 302M audio",
                        Some("drac") => "Dirac",
                        Some("mlpa") => "Dolby TrueHD",
                        _ => "PES private data",
                    }
                }
            }
            0x15 if reg == Some("ID3 ") => "ID3 metadata",
            0x86 if !hdmv => "SCTE-35",
            0x86 => "DTS-HD Master Audio",
            0x80 if hdmv => "LPCM",
            0x82 if hdmv => "DTS",
            0x83 if hdmv => "Dolby TrueHD",
            0x84 if hdmv => "E-AC-3",
            0x85 if hdmv => "DTS-HD High Resolution",
            0x81 => "AC-3",
            0x87 => "E-AC-3",
            0x0f => "AAC",
            0x11 => "AAC (LATM)",
            0x1b => "H.264",
            0x24 => "HEVC",
            0x33 => "VVC",
            0x01 => "MPEG-1 video",
            0x02 => "MPEG-2 video",
            0x03 => "MPEG-1 audio",
            0x04 => "MPEG-2 audio",
            0x10 => "MPEG-4 Visual",
            0x90 => "PGS subtitles",
            0xea => "VC-1",
            _ => return vidutil::lookup_or(STREAM_TYPES, self.kind.into()),
        };
        name.to_owned()
    }

    fn is_scte35(&self, program: Option<[u8; 4]>, m2ts: bool) -> bool {
        self.kind == 0x86 && !(m2ts || program == Some(*b"HDMV"))
    }
}

fn registration(ds: &[(u8, Vec<u8>)]) -> Option<[u8; 4]> {
    let (_, b) = ds.iter().find(|(t, _)| *t == 0x05)?;
    b.get(..4)?.try_into().ok()
}

#[derive(Clone, Debug, Default)]
struct Program {
    number: u16,
    pmt_pid: u16,
    pcr_pid: u16,
    registration: Option<[u8; 4]>,
    streams: Vec<Stream>,
    pmt: Option<Section>,
    service: Option<si::Service>,
}

#[derive(Clone, Debug, Default)]
struct Psi {
    pat: Option<Section>,
    programs: Vec<Program>,
    /// Other tables (CAT, NIT, SDT, EIT, TDT, TOT, SCTE-35, ...).
    tables: Vec<Section>,
    network: Option<String>,
}

impl Psi {
    fn stream(&self, pid: u16) -> Option<(&Program, &Stream)> {
        self.programs
            .iter()
            .find_map(|p| p.streams.iter().find(|s| s.pid == pid).map(|s| (p, s)))
    }

    fn pid_name(&self, pid: u16, m2ts: bool) -> Option<String> {
        match pid {
            0 => return Some("PAT".to_owned()),
            1 => return Some("CAT".to_owned()),
            2 => return Some("TSDT".to_owned()),
            0x10 => return Some("NIT".to_owned()),
            0x11 => return Some("SDT/BAT".to_owned()),
            0x12 => return Some("EIT".to_owned()),
            0x13 => return Some("RST".to_owned()),
            0x14 => return Some("TDT/TOT".to_owned()),
            0x1ffb => return Some("ATSC PSIP".to_owned()),
            0x1fff => return Some("null".to_owned()),
            _ => {}
        }
        if let Some(p) = self.programs.iter().find(|p| p.pmt_pid == pid) {
            return Some(format!("PMT {}", p.number));
        }
        self.stream(pid).map(|(p, s)| s.codec(p.registration, m2ts))
    }

    fn is_section_pid(&self, pid: u16, m2ts: bool) -> bool {
        pid < 0x20
            || pid == 0x1ffb
            || self.programs.iter().any(|p| p.pmt_pid == pid)
            || self.stream(pid).is_some_and(|(p, s)| {
                si::carries_sections(s.kind, s.is_scte35(p.registration, m2ts))
            })
    }
}

#[derive(Clone, Debug)]
struct Ts {
    input: Input,
    layout: Layout,
    count: u64,
    psi: Arc<Psi>,
}

impl Ts {
    /// The whole packet `i` (including any M2TS prefix).
    fn packet(&self, i: u64) -> Span {
        self.input
            .span
            .sub(i.saturating_mul(self.layout.stride), self.layout.stride)
    }

    fn m2ts(&self) -> bool {
        self.layout.prefix == 4
    }
}

const SCAN_PACKETS: u64 = 4096;
const PAGE: u64 = 64;
/// Bytes of a stream's first PES payload kept for its codec details.
const ES_BYTES: usize = 0x1000;
/// Tables kept from the scan.
const MAX_TABLES: usize = 256;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 2048)).await?;
    let probe = Head {
        data: &head,
        tail: &head,
        len: input.span.len,
        len_known: true,
    };
    let layout = layout(&probe).unwrap_or(Layout {
        stride: 188,
        prefix: 0,
    });
    let count = input.span.len.checked_div(layout.stride).unwrap_or(0);
    let mut ts = Ts {
        input,
        layout,
        count,
        psi: Arc::new(Psi::default()),
    };
    let psi = scan(&cx, &ts).await?;
    ts.psi = Arc::new(psi);
    let duration = duration(&cx, &ts).await?;
    cx.annotate(summary(&ts, duration));

    let psi = ts.psi.clone();
    let names: Vec<String> = psi
        .programs
        .iter()
        .filter_map(|p| p.service.as_ref().map(|s| s.name.clone()))
        .filter(|n| !n.is_empty())
        .collect();
    let mut programs = vidutil::plural(to_u64(psi.programs.len()), "program");
    if !names.is_empty() {
        programs = format!("{programs}: {}", names.join(", "));
    }
    cx.emit(
        Node::new("Programs")
            .summary(programs)
            .lazy(programs_node, ts.clone()),
    );
    if !psi.tables.is_empty() {
        let mut kinds: Vec<(&str, u32)> = Vec::new();
        for t in &psi.tables {
            let k = si::table_short(t.table);
            match kinds.iter_mut().find(|(n, _)| *n == k) {
                Some((_, c)) => *c = c.saturating_add(1),
                None => kinds.push((k, 1)),
            }
        }
        let text: Vec<String> = kinds
            .iter()
            .map(|(k, c)| {
                if *c == 1 {
                    (*k).to_owned()
                } else {
                    format!("{k} ×{c}")
                }
            })
            .collect();
        cx.emit(
            Node::new("Service information")
                .summary(text.join(", "))
                .desc("PSI and SI tables found in the first packets, reassembled")
                .lazy(tables_node, ts.clone()),
        );
    }
    let total = ts.layout.stride.saturating_mul(count);
    cx.emit(
        Node::new("PIDs")
            .span(input.span.sub(0, total))
            .summary("packet counts and continuity per PID")
            .desc("Walks every packet of the stream when expanded")
            .lazy(pids_node, ts.clone()),
    );
    cx.emit(
        Node::new("Packets")
            .span(input.span.sub(0, total))
            .summary(format!(
                "{} of {} bytes",
                vidutil::plural(count, "packet"),
                ts.layout.stride
            ))
            .lazy(packets, ts.clone()),
    );
    if input.span.len > total {
        cx.emit(Node::new("Trailing bytes").span(input.span.tail(total)));
    }
    Ok(())
}

fn summary(ts: &Ts, duration: Option<f64>) -> String {
    let mut parts = vec![match ts.layout.stride {
        192 => "BDAV MPEG-TS (192-byte packets)".to_owned(),
        204 => "MPEG-TS (204-byte packets)".to_owned(),
        _ => "MPEG-TS".to_owned(),
    }];
    if ts.psi.programs.len() > 1 {
        parts.push(vidutil::plural(to_u64(ts.psi.programs.len()), "program"));
    } else if let Some(s) = ts.psi.programs.first().and_then(|p| p.service.as_ref())
        && !s.name.is_empty()
    {
        parts.push(format!("“{}”", s.name));
    }
    let streams: Vec<String> = ts
        .psi
        .programs
        .iter()
        .flat_map(|p| {
            p.streams.iter().map(move |s| {
                let mut c = stream_text(&s.codec(p.registration, ts.m2ts()), s.detail.as_deref());
                if let Some(l) = s.language() {
                    c = format!("{c} [{l}]");
                }
                c
            })
        })
        .collect();
    if !streams.is_empty() {
        parts.push(streams.join(" + "));
    }
    if let Some(d) = duration {
        parts.push(vidutil::seconds_f64(d));
    }
    parts.push(vidutil::plural(ts.count, "packet"));
    parts.join(", ")
}

/// A stream's codec with its details: the details alone when they name
/// the codec themselves ("AC-3, 192 kb/s, ...", "MPEG-2 video, ...").
fn stream_text(codec: &str, detail: Option<&str>) -> String {
    match detail {
        Some(d)
            if d.starts_with(codec)
                || ["MPEG-", "AAC", "HE-AAC", "AC-3", "E-AC-3", "DTS"]
                    .iter()
                    .any(|p| d.starts_with(p)) =>
        {
            d.to_owned()
        }
        Some(d) => format!("{codec} {d}"),
        None => codec.to_owned(),
    }
}

/// Payload of a 188-byte packet `p` (starting at the sync byte): offset and
/// whether it starts a unit.
fn payload_start(p: &[u8]) -> Option<(usize, bool)> {
    let pusi = p.get(1)? & 0x40 != 0;
    let afc = (p.get(3)? >> 4) & 3;
    let mut at = 4usize;
    if afc & 2 != 0 {
        at = at.checked_add(1)?.checked_add(usize::from(*p.get(4)?))?;
    }
    if afc & 1 == 0 || at >= 188 {
        return None;
    }
    Some((at, pusi))
}

fn pid_of(p: &[u8]) -> u16 {
    u16_be(p, 1).unwrap_or(0) & 0x1fff
}

// ---------------------------------------------------------------------------
// Section reassembly

#[derive(Default)]
struct Assembly {
    data: Vec<u8>,
    pieces: Vec<Span>,
    need: usize,
}

impl Assembly {
    fn add(&mut self, bytes: &[u8], span: Span) {
        let take = self.need.saturating_sub(self.data.len()).min(bytes.len());
        self.data
            .extend_from_slice(bytes.get(..take).unwrap_or_default());
        if take > 0 {
            self.pieces.push(span.sub(0, to_u64(take)));
        }
    }

    fn complete(&self) -> bool {
        self.need > 0 && self.data.len() >= self.need
    }

    fn take(&mut self) -> (Vec<u8>, Vec<Span>) {
        self.need = 0;
        (
            std::mem::take(&mut self.data),
            std::mem::take(&mut self.pieces),
        )
    }
}

/// Feeds a packet payload (`p`, at `span`) to a PID's section assembly;
/// completed sections are appended to `done`.
fn feed(st: &mut Assembly, pusi: bool, p: &[u8], span: Span, done: &mut Vec<(Vec<u8>, Vec<Span>)>) {
    if !pusi {
        if st.need > 0 {
            st.add(p, span);
            if st.complete() {
                done.push(st.take());
            }
        }
        return;
    }
    let pointer = usize::from(p.first().copied().unwrap_or(0));
    if st.need > 0 {
        let end = pointer.saturating_add(1).min(p.len());
        st.add(
            p.get(1..end).unwrap_or_default(),
            span.sub(1, to_u64(pointer)),
        );
        if st.complete() {
            done.push(st.take());
        }
    }
    st.take();
    let mut at = pointer.saturating_add(1);
    while let Some(rest) = p.get(at..) {
        if rest.len() < 3 || rest.first() == Some(&0xff) {
            break;
        }
        let len = usize::from(u16_be(rest, 1).unwrap_or(0) & 0x0fff);
        if len > 4093 {
            break;
        }
        st.need = len.saturating_add(3);
        st.add(rest, span.sub(to_u64(at), u64::MAX));
        if !st.complete() {
            break;
        }
        done.push(st.take());
        at = at.saturating_add(len).saturating_add(3);
    }
}

/// A span for a reassembled section: the piece itself, or a pieces source.
fn section_span(cx: &Cx, file: Span, pieces: &[Span]) -> Result<Span> {
    match pieces {
        [one] => Ok(*one),
        _ => {
            let first = pieces.first().map_or(file.offset, |s| s.offset);
            let last = pieces.last().map_or(first, Span::end);
            let parent = Span::new(file.source, first, last.saturating_sub(first));
            cx.add_pieces(
                Origin {
                    parent,
                    transform: "mpegts-section",
                },
                pieces.to_vec(),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Scan

/// First-PES capture of an elementary stream.
#[derive(Default)]
struct Capture {
    data: Vec<u8>,
    started: bool,
    done: bool,
    pts: Option<u64>,
}

/// Reads the PSI/SI and the first PES packet of each stream from the first
/// packets.
async fn scan(cx: &Cx, ts: &Ts) -> Result<Psi> {
    let mut psi = Psi::default();
    let limit = ts.count.min(SCAN_PACKETS);
    let mut asm: BTreeMap<u16, Assembly> = BTreeMap::new();
    let mut seen: BTreeSet<(u16, u8, u16, u8, u8)> = BTreeSet::new();
    let mut captures: BTreeMap<u16, Capture> = BTreeMap::new();
    let m2ts = ts.m2ts();
    let mut i = 0u64;
    while i < limit {
        let n = limit.saturating_sub(i).min(PAGE);
        let page = ts.input.span.sub(
            i.saturating_mul(ts.layout.stride),
            n.saturating_mul(ts.layout.stride),
        );
        let data = cx.read_avail(page).await?;
        for j in 0..n {
            let at = vidutil::us(
                j.saturating_mul(ts.layout.stride)
                    .saturating_add(ts.layout.prefix),
            );
            let Some(p) = data.get(at..at.saturating_add(188)) else {
                break;
            };
            if p.first() != Some(&0x47) {
                continue;
            }
            let pid = pid_of(p);
            let Some((start, pusi)) = payload_start(p) else {
                continue;
            };
            let payload = p.get(start..).unwrap_or_default();
            let pspan = page.sub(to_u64(at.saturating_add(start)), to_u64(payload.len()));
            if psi.is_section_pid(pid, m2ts) {
                let mut done = Vec::new();
                feed(asm.entry(pid).or_default(), pusi, payload, pspan, &mut done);
                for (bytes, pieces) in done {
                    let span = section_span(cx, ts.input.span, &pieces)?;
                    take_section(&mut psi, &mut seen, pid, &bytes, span, m2ts);
                }
            } else if psi.stream(pid).is_some() {
                let c = captures.entry(pid).or_default();
                capture(c, pusi, payload);
            }
        }
        i = i.saturating_add(n);
        let streams_done = psi
            .programs
            .iter()
            .flat_map(|p| p.streams.iter())
            .filter(|s| !si::carries_sections(s.kind, s.kind == 0x86))
            .all(|s| captures.get(&s.pid).is_some_and(|c| c.done));
        let pmts_done = psi.programs.iter().all(|p| p.pmt.is_some());
        let sdt = psi.tables.iter().any(|t| t.table == 0x42);
        if psi.pat.is_some() && pmts_done && streams_done && (sdt || i >= 1024) {
            break;
        }
    }
    // Codec details from the captured payloads.
    for prog in &mut psi.programs {
        let reg = prog.registration;
        for s in &mut prog.streams {
            if let Some(c) = captures.get(&s.pid) {
                s.first_pts = c.pts;
                let codec = s.codec(reg, m2ts);
                s.detail = es_detail(&codec, &c.data);
            }
        }
    }
    Ok(psi)
}

/// Appends a payload to a stream's first-PES capture.
fn capture(c: &mut Capture, pusi: bool, payload: &[u8]) {
    if c.done {
        return;
    }
    if pusi {
        if c.started {
            c.done = true;
            return;
        }
        if !payload.starts_with(&[0, 0, 1]) {
            return;
        }
        c.started = true;
        c.pts = pes_times(payload).0;
        let header = pes_payload_offset(payload);
        c.data
            .extend_from_slice(payload.get(vidutil::us(header)..).unwrap_or_default());
    } else if c.started {
        let room = ES_BYTES.saturating_sub(c.data.len());
        c.data
            .extend_from_slice(payload.get(..room.min(payload.len())).unwrap_or_default());
    }
    if c.data.len() >= ES_BYTES {
        c.done = true;
    }
}

/// Codec details from the start of a stream's first PES payload.
fn es_detail(codec: &str, d: &[u8]) -> Option<String> {
    match codec {
        "H.264" | "HEVC" => {
            let nal = if codec == "H.264" {
                NalCodec::Avc
            } else {
                NalCodec::Hevc
            };
            let want = if codec == "H.264" { 7 } else { 33 };
            let mut at = 0usize;
            for _ in 0..64 {
                let i = vidutil::find(d.get(at..)?, &[0, 0, 1])?;
                let start = at.saturating_add(i).saturating_add(3);
                let unit = d.get(start..)?;
                if unit.first().map(|&b| u64::from(nal.nal_type(b))) == Some(want) {
                    let len = vidutil::find(unit, &[0, 0, 1]).unwrap_or(unit.len());
                    let span = Span::new(crate::span::SourceId::default_host(), 0, to_u64(len));
                    let (info, _) = vidutil::parse_nal(
                        nal,
                        unit.get(..len)?,
                        span,
                        &ParamSets::default(),
                        false,
                    );
                    return info.sps.map(|s| s.describe());
                }
                at = start;
            }
            None
        }
        "MPEG-1 video" | "MPEG-2 video" => super::video::es_summary(d),
        "MPEG-4 Visual" => super::mpeg4::es_summary(d),
        "AAC" | "AC-3" | "E-AC-3" | "DTS" | "MPEG-1 audio" | "MPEG-2 audio" => {
            vidutil::audio::es_summary(d)
        }
        _ => None,
    }
}

/// Files a reassembled section: PAT, PMT and SDT feed the program model,
/// the rest is kept for display.
fn take_section(
    psi: &mut Psi,
    seen: &mut BTreeSet<(u16, u8, u16, u8, u8)>,
    pid: u16,
    d: &[u8],
    span: Span,
    m2ts: bool,
) {
    let table = d.first().copied().unwrap_or(0xff);
    if table == 0xff {
        return;
    }
    let syntax = d.get(1).is_some_and(|b| b & 0x80 != 0);
    let key = if syntax {
        (
            pid,
            table,
            u16_be(d, 3).unwrap_or(0),
            (d.get(5).copied().unwrap_or(0) >> 1) & 0x1f,
            d.get(6).copied().unwrap_or(0),
        )
    } else {
        (pid, table, 0, 0, 0)
    };
    if !seen.insert(key) {
        return;
    }
    let (decoded, _) = si::section(d, span, false);
    let section = Section {
        pid,
        table,
        span,
        summary: decoded.summary.clone(),
        crc_ok: si::crc_ok(d),
    };
    match table {
        0x00 if pid == 0 && psi.pat.is_none() => {
            for (number, pmt_pid) in decoded.pat {
                if number != 0 {
                    psi.programs.push(Program {
                        number,
                        pmt_pid,
                        pcr_pid: 0x1fff,
                        ..Program::default()
                    });
                }
            }
            psi.pat = Some(section);
        }
        0x02 => {
            let number = u16_be(d, 3).unwrap_or(0);
            let Some(prog) = psi
                .programs
                .iter_mut()
                .find(|p| p.pmt_pid == pid && p.number == number && p.pmt.is_none())
            else {
                return;
            };
            if let Some(pmt) = decoded.pmt {
                prog.pcr_pid = pmt.pcr_pid;
                prog.registration = registration(&pmt.program_info);
                prog.streams = pmt
                    .streams
                    .into_iter()
                    .map(|s| Stream {
                        pid: s.pid,
                        kind: s.kind,
                        span: Some(span.sub(to_u64(s.offset), to_u64(s.len))),
                        descriptors: s.descriptors,
                        ..Stream::default()
                    })
                    .collect();
            }
            prog.pmt = Some(section);
        }
        _ => {
            if table == 0x42 {
                for s in decoded.services {
                    if let Some(p) = psi.programs.iter_mut().find(|p| p.number == s.id) {
                        p.service = Some(s);
                    }
                }
            }
            if matches!(table, 0x40) && psi.network.is_none() {
                psi.network = decoded.network;
            }
            let _ = m2ts;
            if psi.tables.len() < MAX_TABLES {
                psi.tables.push(section);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Duration

/// Duration from the first and last PCR of the first program's PCR PID,
/// or from the PTS of its first stream.
async fn duration(cx: &Cx, ts: &Ts) -> Result<Option<f64>> {
    let Some(prog) = ts.psi.programs.first() else {
        return Ok(None);
    };
    let window = ts.count.min(256);
    let tail = ts.count.saturating_sub(window);
    let pid = prog.pcr_pid;
    let first = find_clock(cx, ts, pid, 0, window, false, Clock::Pcr).await?;
    let last = find_clock(cx, ts, pid, tail, window, true, Clock::Pcr).await?;
    if let (Some(a), Some(b)) = (first, last)
        && b > a
    {
        return Ok(Some(b.saturating_sub(a) as f64 / 27_000_000.0));
    }
    let Some(stream) = prog.streams.first() else {
        return Ok(None);
    };
    let first = stream.first_pts;
    let last = find_clock(cx, ts, stream.pid, tail, window, true, Clock::Pts).await?;
    Ok(match (first, last) {
        (Some(a), Some(b)) if b > a => Some(b.saturating_sub(a) as f64 / 90_000.0),
        _ => None,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Clock {
    Pcr,
    Pts,
}

async fn find_clock(
    cx: &Cx,
    ts: &Ts,
    pid: u16,
    from: u64,
    n: u64,
    last: bool,
    clock: Clock,
) -> Result<Option<u64>> {
    let page = ts.input.span.sub(
        from.saturating_mul(ts.layout.stride),
        n.saturating_mul(ts.layout.stride),
    );
    let data = cx.read_avail(page).await?;
    let mut found = None;
    for j in 0..n {
        let at = vidutil::us(
            j.saturating_mul(ts.layout.stride)
                .saturating_add(ts.layout.prefix),
        );
        let Some(p) = data.get(at..at.saturating_add(188)) else {
            break;
        };
        if pid_of(p) != pid {
            continue;
        }
        let v = match clock {
            Clock::Pcr => pcr(p),
            Clock::Pts => match payload_start(p) {
                Some((start, true)) => pes_times(p.get(start..).unwrap_or_default()).0,
                _ => None,
            },
        };
        if let Some(v) = v {
            found = Some(v);
            if !last {
                break;
            }
        }
    }
    Ok(found)
}

/// The PCR (27 MHz) of a packet, if its adaptation field carries one.
fn pcr(p: &[u8]) -> Option<u64> {
    let afc = (p.get(3)? >> 4) & 3;
    if afc & 2 == 0 || *p.get(4)? < 7 || p.get(5)? & 0x10 == 0 {
        return None;
    }
    clock_42(p.get(6..12)?)
}

/// A 33-bit base and 9-bit extension (PCR, OPCR) in 27 MHz units.
fn clock_42(b: &[u8]) -> Option<u64> {
    let g = |i: usize| b.get(i).copied().map(u64::from);
    let base = g(0)? << 25 | g(1)? << 17 | g(2)? << 9 | g(3)? << 1 | g(4)? >> 7;
    let ext = (g(4)? & 1) << 8 | g(5)?;
    base.checked_mul(300)?.checked_add(ext)
}

fn seconds_27m(v: u64) -> String {
    format!("{:.6} s", v as f64 / 27_000_000.0)
}

// ---------------------------------------------------------------------------
// Programs and tables

async fn programs_node(cx: Cx, ts: Ts) -> Result<()> {
    if let Some(pat) = &ts.psi.pat {
        cx.emit(section_node(pat));
    }
    if let Some(n) = &ts.psi.network {
        cx.emit(Node::new("Network").value(Value::Text(n.clone())));
    }
    for (i, p) in ts.psi.programs.iter().enumerate() {
        let mut parts = Vec::new();
        if let Some(s) = &p.service {
            parts.push(if s.provider.is_empty() {
                s.name.clone()
            } else {
                format!("{} ({})", s.name, s.provider)
            });
        }
        parts.push(format!(
            "PMT PID {:#06x}, PCR PID {:#06x}",
            p.pmt_pid, p.pcr_pid
        ));
        let streams: Vec<String> = p
            .streams
            .iter()
            .map(|s| s.codec(p.registration, ts.m2ts()))
            .collect();
        if !streams.is_empty() {
            parts.push(streams.join(" + "));
        }
        let mut node = Node::new(format!("Program {}", p.number)).summary(parts.join(", "));
        if let Some(s) = &p.pmt {
            node = node.span(s.span);
        }
        cx.push(node.lazy(program, (ts.clone(), i))).await;
    }
    Ok(())
}

fn section_node(s: &Section) -> Node {
    let mut node = Node::new(si::table_name(s.table))
        .span(s.span)
        .lazy(section, s.span);
    let mut summary = format!("PID {:#06x}", s.pid);
    if let Some(t) = &s.summary
        && !t.is_empty()
    {
        summary = format!("{summary}, {t}");
    }
    node = node.summary(summary);
    if s.crc_ok == Some(false) {
        node = node.diag(Diagnostic::warning("CRC mismatch"));
    }
    node
}

async fn program(cx: Cx, (ts, index): (Ts, usize)) -> Result<()> {
    let Some(p) = ts.psi.programs.get(index) else {
        return Ok(());
    };
    if let Some(s) = &p.service {
        cx.emit(
            Node::new("Service name")
                .value(Value::Text(s.name.clone()))
                .summary(vidutil::lookup_or(si::SERVICE_TYPES, s.kind.into())),
        );
        if !s.provider.is_empty() {
            cx.emit(Node::new("Service provider").value(Value::Text(s.provider.clone())));
        }
    }
    if let Some(s) = &p.pmt {
        cx.emit(section_node(s));
    }
    for s in &p.streams {
        let codec = stream_text(&s.codec(p.registration, ts.m2ts()), s.detail.as_deref());
        let mut extras = Vec::new();
        if let Some(l) = s.language() {
            extras.push(format!("language {l}"));
        }
        if let Some(t) = s.first_pts {
            extras.push(format!("first PTS {}", seconds_90k(t)));
        }
        let mut summary = codec;
        if !extras.is_empty() {
            summary = format!("{summary}: {}", extras.join(", "));
        }
        let mut node = Node::new(format!("PID {:#06x}", s.pid))
            .value(Value::Enum {
                raw: s.kind.into(),
                bits: 8,
                name: crate::value::lookup(STREAM_TYPES, s.kind.into()),
            })
            .summary(summary);
        if let Some(span) = s.span {
            node = node.span(span).lazy(es_entry, span);
        }
        cx.emit(node);
    }
    Ok(())
}

/// A PMT stream entry with its descriptors.
async fn es_entry(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span).await?;
    let mut w = vidutil::bitwalk::Walker::new(&d, span, false, true);
    let ok = (|| {
        w.en("stream_type", 8, STREAM_TYPES)?;
        w.u("reserved", 3)?;
        w.x("elementary_PID", 13)?;
        w.u("reserved", 4)?;
        let n = usize::try_from(w.u("ES_info_length", 12)?).ok()?;
        si::descriptor_loop(&mut w, n)
    })()
    .is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
    Ok(())
}

async fn tables_node(cx: Cx, ts: Ts) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(ts.psi.tables.len())));
    for t in &ts.psi.tables {
        cx.push(section_node(t)).await;
    }
    Ok(())
}

/// Decodes a section in full.
async fn section(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 4096)).await?;
    let (_, nodes) = si::section(&d, span, true);
    for node in nodes {
        cx.emit(node);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-PID statistics

#[derive(Clone, Copy, Default)]
struct PidStats {
    packets: u64,
    first: u64,
    unit_starts: u64,
    pcrs: u64,
    scrambled: u64,
    transport_errors: u64,
    cc_errors: u64,
    first_cc_error: Option<u64>,
    discontinuities: u64,
    last_cc: Option<u8>,
    duplicate: bool,
}

async fn pids_node(cx: Cx, ts: Ts) -> Result<()> {
    let mut stats: BTreeMap<u16, PidStats> = BTreeMap::new();
    let mut lost = 0u64;
    let stride = ts.layout.stride;
    let mut i = 0u64;
    while i < ts.count {
        let n = ts.count.saturating_sub(i).min(PAGE);
        let page = ts
            .input
            .span
            .sub(i.saturating_mul(stride), n.saturating_mul(stride));
        let data = cx.read_avail(page).await?;
        for j in 0..n {
            let at = vidutil::us(j.saturating_mul(stride).saturating_add(ts.layout.prefix));
            let Some(p) = data.get(at..at.saturating_add(188)) else {
                break;
            };
            if p.first() != Some(&0x47) {
                lost = lost.saturating_add(1);
                continue;
            }
            let pid = pid_of(p);
            let b1 = p.get(1).copied().unwrap_or(0);
            let b3 = p.get(3).copied().unwrap_or(0);
            let s = stats.entry(pid).or_insert(PidStats {
                first: i.saturating_add(j),
                ..PidStats::default()
            });
            s.packets = s.packets.saturating_add(1);
            if b1 & 0x80 != 0 {
                s.transport_errors = s.transport_errors.saturating_add(1);
            }
            if b1 & 0x40 != 0 {
                s.unit_starts = s.unit_starts.saturating_add(1);
            }
            if b3 & 0xc0 != 0 {
                s.scrambled = s.scrambled.saturating_add(1);
            }
            if pcr(p).is_some() {
                s.pcrs = s.pcrs.saturating_add(1);
            }
            let afc = (b3 >> 4) & 3;
            let discontinuity = afc & 2 != 0
                && p.get(4).is_some_and(|&l| l > 0)
                && p.get(5).is_some_and(|f| f & 0x80 != 0);
            if discontinuity {
                s.discontinuities = s.discontinuities.saturating_add(1);
            }
            let cc = b3 & 15;
            if pid != 0x1fff {
                if let Some(last) = s.last_cc
                    && !discontinuity
                {
                    let expected = if afc & 1 != 0 {
                        last.wrapping_add(1) & 15
                    } else {
                        last
                    };
                    if cc == last && afc & 1 != 0 && !s.duplicate {
                        // One duplicate packet is allowed.
                        s.duplicate = true;
                    } else if cc != expected {
                        s.cc_errors = s.cc_errors.saturating_add(1);
                        s.first_cc_error.get_or_insert(i.saturating_add(j));
                        s.duplicate = false;
                    } else {
                        s.duplicate = false;
                    }
                }
                s.last_cc = Some(cc);
            }
        }
        i = i.saturating_add(n);
        cx.progress(i, ts.count);
        cx.checkpoint().await;
    }
    let total = ts.count.max(1);
    if lost > 0 {
        cx.emit(
            uint("Packets without sync byte", ts.input.span, lost, 64)
                .diag(Diagnostic::warning("lost sync")),
        );
    }
    for (pid, s) in stats {
        let mut parts = Vec::new();
        if let Some(name) = ts.psi.pid_name(pid, ts.m2ts()) {
            parts.push(name);
        }
        let share = s.packets as f64 * 100.0 / total as f64;
        parts.push(format!(
            "{} ({share:.1}%)",
            vidutil::plural(s.packets, "packet")
        ));
        if s.cc_errors > 0 {
            parts.push(vidutil::plural(s.cc_errors, "continuity error"));
        }
        if s.scrambled > 0 {
            parts.push(format!("{} scrambled", s.scrambled));
        }
        let mut node = Node::new(format!("PID {pid:#06x}"))
            .summary(parts.join(", "))
            .lazy(
                crate::formats::util::arcutil::emit_nodes,
                Arc::new(pid_fields(&ts, s)),
            );
        if s.cc_errors > 0 {
            node = node.diag(Diagnostic::warning(format!(
                "{} continuity counter errors",
                s.cc_errors
            )));
        }
        cx.emit(node);
    }
    Ok(())
}

fn pid_fields(ts: &Ts, s: PidStats) -> Vec<Node> {
    let first = ts.packet(s.first);
    let mut out = vec![
        uint("Packets", first, s.packets, 64),
        uint("First packet", first, s.first, 64),
        uint("Payload unit starts", first, s.unit_starts, 64),
        uint("PCRs", first, s.pcrs, 64),
        uint("Continuity errors", first, s.cc_errors, 64),
        uint("Discontinuity indicators", first, s.discontinuities, 64),
        uint("Scrambled packets", first, s.scrambled, 64),
        uint("Transport errors", first, s.transport_errors, 64),
    ];
    if let Some(e) = s.first_cc_error {
        out.push(uint("First continuity error", ts.packet(e), e, 64).summary("packet index"));
    }
    out
}

// ---------------------------------------------------------------------------
// Packets

async fn packets(cx: Cx, ts: Ts) -> Result<()> {
    cx.set_count(Count::Exact(ts.count));
    let stride = ts.layout.stride;
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < ts.count {
        let n = ts.count.saturating_sub(i).min(PAGE);
        let page = ts
            .input
            .span
            .sub(i.saturating_mul(stride), n.saturating_mul(stride));
        let data = cx.read_avail(page).await?;
        for j in 0..n {
            let at = vidutil::us(j.saturating_mul(stride));
            let raw = data
                .get(at..at.saturating_add(vidutil::us(stride)))
                .unwrap_or_default();
            let index = i.saturating_add(j);
            let span = ts.packet(index);
            let p = raw.get(vidutil::us(ts.layout.prefix)..).unwrap_or_default();
            cx.mark(move || index);
            cx.push(
                Node::new(format!("Packet {index}"))
                    .span(span)
                    .summary(packet_summary(&ts, p))
                    .lazy(packet, (ts.clone(), index)),
            )
            .await;
        }
        i = i.saturating_add(n);
    }
    Ok(())
}

fn packet_summary(ts: &Ts, p: &[u8]) -> String {
    if p.first() != Some(&0x47) {
        return "lost sync".to_owned();
    }
    let psi = &ts.psi;
    let pid = pid_of(p);
    let mut s = format!("PID {pid:#06x}");
    if let Some(name) = psi.pid_name(pid, ts.m2ts()) {
        s = format!("{s} ({name})");
    }
    if let Some((start, true)) = payload_start(p) {
        let payload = p.get(start..).unwrap_or_default();
        if payload.starts_with(&[0, 0, 1]) {
            s = format!("{s}, {}", pes_summary(payload));
        } else if psi.is_section_pid(pid, ts.m2ts()) {
            let pointer = usize::from(payload.first().copied().unwrap_or(0));
            let table = payload
                .get(pointer.saturating_add(1))
                .copied()
                .unwrap_or(0xff);
            if table != 0xff {
                s = format!("{s}, {} section", si::table_short(table));
            }
        } else {
            s.push_str(", unit start");
        }
    }
    if let Some(v) = pcr(p) {
        s = format!("{s}, PCR {}", seconds_27m(v));
    }
    if p.get(3).is_some_and(|b| b & 0xc0 != 0) {
        s.push_str(", scrambled");
    }
    s
}

async fn packet(cx: Cx, (ts, index): (Ts, u64)) -> Result<()> {
    let whole = ts.packet(index);
    let data = cx.read_avail(whole).await?;
    if ts.layout.prefix == 4 {
        let tc = u32_be(&data, 0).unwrap_or(0);
        let ats = u64::from(tc & 0x3fff_ffff);
        cx.emit(uint(
            "Copy permission indicator",
            whole.sub(0, 4),
            (tc >> 30).into(),
            2,
        ));
        cx.emit(
            uint("Arrival timestamp", whole.sub(0, 4), ats, 30)
                .summary(seconds_27m(ats))
                .desc("27 MHz clock, modulo 2^30"),
        );
    }
    let span = whole.sub(ts.layout.prefix, 188);
    let p = data
        .get(vidutil::us(ts.layout.prefix)..)
        .unwrap_or_default();
    let p = p.get(..188.min(p.len())).unwrap_or_default();
    let mut sync = hex(
        "Sync byte",
        span.sub(0, 1),
        p.first().copied().unwrap_or(0).into(),
        8,
    );
    if p.first() != Some(&0x47) {
        sync = sync.diag(crate::error::Diagnostic::malformed("expected 0x47"));
    }
    cx.emit(sync);
    let w = u16_be(p, 1).unwrap_or(0);
    let s12 = span.sub(1, 2);
    cx.emit(flag_node("Transport error", s12, w & 0x8000 != 0));
    cx.emit(flag_node("Payload unit start", s12, w & 0x4000 != 0));
    cx.emit(flag_node("Transport priority", s12, w & 0x2000 != 0));
    let pid = w & 0x1fff;
    let mut pid_node = hex("PID", s12, pid.into(), 13);
    if let Some(name) = ts.psi.pid_name(pid, ts.m2ts()) {
        pid_node = pid_node.summary(name);
    }
    cx.emit(pid_node);
    let b3 = p.get(3).copied().unwrap_or(0);
    let s3 = span.sub(3, 1);
    cx.emit(enumerated(
        "Scrambling control",
        s3,
        (b3 >> 6).into(),
        2,
        SCRAMBLING,
    ));
    cx.emit(enumerated(
        "Adaptation field control",
        s3,
        ((b3 >> 4) & 3).into(),
        2,
        ADAPTATION,
    ));
    cx.emit(uint("Continuity counter", s3, (b3 & 15).into(), 4));
    let mut at = 4usize;
    if b3 & 0x20 != 0 {
        let len = usize::from(p.get(4).copied().unwrap_or(0));
        let af = vidutil::at(span, 4, len.saturating_add(1));
        let mut flags = Vec::new();
        let f = p.get(5).copied().unwrap_or(0);
        if len > 0 {
            for (bit, name) in [
                (0x80, "discontinuity"),
                (0x40, "random access"),
                (0x10, "PCR"),
                (0x04, "splice point"),
                (0x02, "private data"),
            ] {
                if f & bit != 0 {
                    flags.push(name);
                }
            }
        }
        let mut summary = flags.join(", ");
        if let Some(v) = pcr(p) {
            summary = format!("{summary} {}", seconds_27m(v));
        }
        if summary.is_empty() {
            summary = format!("stuffing, {} bytes", len.saturating_add(1));
        }
        cx.emit(
            Node::new("Adaptation field")
                .span(af)
                .summary(summary)
                .lazy(adaptation, af),
        );
        at = at.saturating_add(1).saturating_add(len);
    }
    if b3 & 0x10 == 0 || at >= p.len() {
        return Ok(());
    }
    let payload_span = vidutil::at(span, at, p.len().saturating_sub(at));
    let payload = p.get(at..).unwrap_or_default();
    if w & 0x4000 != 0 && payload.starts_with(&[0, 0, 1]) {
        let header = pes_payload_offset(payload);
        let head = payload_span.sub(0, header);
        cx.emit(
            Node::new("PES header")
                .span(head)
                .summary(pes_summary(payload))
                .lazy(pes, head),
        );
        let rest = payload_span.tail(header);
        let mut node = Node::new("PES payload")
            .span(rest)
            .summary(format!("{} bytes", rest.len));
        if let Some((prog, s)) = ts.psi.stream(pid)
            && let Some(d) = payload.get(vidutil::us(header)..)
        {
            let codec = s.codec(prog.registration, ts.m2ts());
            if let Some(detail) = vidutil::audio::es_summary(d).filter(|_| {
                matches!(
                    codec.as_str(),
                    "AAC" | "AC-3" | "E-AC-3" | "DTS" | "MPEG-1 audio" | "MPEG-2 audio"
                )
            }) {
                node = node.summary(format!("{detail}, {} bytes", rest.len));
            }
        }
        cx.emit(node);
    } else if ts.psi.is_section_pid(pid, ts.m2ts()) {
        if w & 0x4000 != 0 {
            let pointer = u64::from(payload.first().copied().unwrap_or(0));
            cx.emit(uint("Pointer field", payload_span.sub(0, 1), pointer, 8));
            if pointer > 0 {
                cx.emit(Node::new("End of previous section").span(payload_span.sub(1, pointer)));
            }
            let body_at = pointer.saturating_add(1);
            let body = payload.get(vidutil::us(body_at)..).unwrap_or_default();
            let table = body.first().copied().unwrap_or(0xff);
            if table == 0xff {
                cx.emit(Node::new("Stuffing").span(payload_span.tail(body_at)));
            } else {
                let len = u16_be(body, 1).map_or(0, |l| u64::from(l & 0x0fff).saturating_add(3));
                let sec = payload_span.sub(body_at, len);
                let mut node =
                    Node::new(si::table_name(table))
                        .span(sec)
                        .summary(if sec.len < len {
                            format!("start of a {len}-byte section, continued in later packets")
                        } else {
                            format!("{len} bytes")
                        });
                if sec.len == len {
                    node = node.lazy(section, sec);
                }
                cx.emit(node);
                let after = body_at.saturating_add(len);
                if after < payload_span.len {
                    cx.emit(
                        Node::new("Following sections / stuffing").span(payload_span.tail(after)),
                    );
                }
            }
        } else {
            cx.emit(
                Node::new("Section continuation")
                    .span(payload_span)
                    .summary(format!("{} bytes", payload_span.len)),
            );
        }
    } else {
        cx.emit(
            Node::new("Payload")
                .span(payload_span)
                .summary(format!("{} bytes", payload_span.len)),
        );
    }
    Ok(())
}

/// Where the payload of a PES packet starting with `d` begins.
fn pes_payload_offset(d: &[u8]) -> u64 {
    let id = d.get(3).copied().unwrap_or(0);
    if super::has_optional_header(id) && d.get(6).is_some_and(|b| b & 0xc0 == 0x80) {
        9u64.saturating_add(d.get(8).copied().unwrap_or(0).into())
    } else {
        6
    }
}

async fn pes(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 300)).await?;
    pes_header(&cx, span, &d);
    Ok(())
}

async fn adaptation(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span).await?;
    let len = d.first().copied().unwrap_or(0);
    cx.emit(uint(
        "Adaptation field length",
        span.sub(0, 1),
        len.into(),
        8,
    ));
    if len == 0 {
        return Ok(());
    }
    let flags = d.get(1).copied().unwrap_or(0);
    let mut set = Vec::new();
    for (bit, name) in [
        (0x80, "DISCONTINUITY"),
        (0x40, "RANDOM_ACCESS"),
        (0x20, "ES_PRIORITY"),
        (0x10, "PCR"),
        (0x08, "OPCR"),
        (0x04, "SPLICING_POINT"),
        (0x02, "PRIVATE_DATA"),
        (0x01, "EXTENSION"),
    ] {
        if flags & bit != 0 {
            set.push(name);
        }
    }
    cx.emit(Node::new("Flags").span(span.sub(1, 1)).value(Value::Flags {
        raw: flags.into(),
        bits: 8,
        set,
        unknown: 0,
    }));
    let end = usize::from(len).saturating_add(1);
    let mut at = 2usize;
    let pos = |a: usize| to_u64(a);
    if flags & 0x10 != 0 {
        if let Some(v) = d.get(at..at.saturating_add(6)).and_then(clock_42) {
            cx.emit(
                uint("PCR", span.sub(pos(at), 6), v, 42)
                    .summary(seconds_27m(v))
                    .desc("Program clock reference: 33-bit base (90 kHz) × 300 + 9-bit extension"),
            );
        }
        at = at.saturating_add(6);
    }
    if flags & 0x08 != 0 {
        if let Some(v) = d.get(at..at.saturating_add(6)).and_then(clock_42) {
            cx.emit(uint("OPCR", span.sub(pos(at), 6), v, 42).summary(seconds_27m(v)));
        }
        at = at.saturating_add(6);
    }
    if flags & 0x04 != 0 {
        let c = d.get(at).copied().unwrap_or(0);
        cx.emit(
            Node::new("Splice countdown")
                .span(span.sub(pos(at), 1))
                .value(Value::Int {
                    value: i8::from_ne_bytes([c]).into(),
                    bits: 8,
                }),
        );
        at = at.saturating_add(1);
    }
    if flags & 0x02 != 0 {
        let n = usize::from(d.get(at).copied().unwrap_or(0));
        cx.emit(uint(
            "Transport private data length",
            span.sub(pos(at), 1),
            to_u64(n),
            8,
        ));
        let data = span.sub(pos(at.saturating_add(1)), pos(n));
        let bytes = d
            .get(at.saturating_add(1)..at.saturating_add(1).saturating_add(n))
            .unwrap_or_default();
        let mut node = Node::new("Transport private data")
            .span(data)
            .summary(format!("{n} bytes"));
        if bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ') && !bytes.is_empty() {
            node = node.value(Value::Text(String::from_utf8_lossy(bytes).into_owned()));
        }
        cx.emit(node);
        at = at.saturating_add(1).saturating_add(n);
    }
    if flags & 0x01 != 0 && at < end {
        let n = usize::from(d.get(at).copied().unwrap_or(0));
        let ext = span.sub(pos(at), pos(n.saturating_add(1)));
        let ef = d.get(at.saturating_add(1)).copied().unwrap_or(0);
        let mut parts = Vec::new();
        let mut k = at.saturating_add(2);
        if ef & 0x80 != 0 {
            let v = u16_be(&d, k).unwrap_or(0);
            if v & 0x8000 != 0 {
                parts.push(format!("legal time window offset {}", v & 0x7fff));
            }
            k = k.saturating_add(2);
        }
        if ef & 0x40 != 0 {
            let v = crate::bytes::u24_be(&d, k).unwrap_or(0) & 0x3f_ffff;
            parts.push(format!("piecewise rate {v}"));
            k = k.saturating_add(3);
        }
        if ef & 0x20 != 0 {
            let t = d.get(k).copied().unwrap_or(0) >> 4;
            let dts = d.get(k..k.saturating_add(5)).and_then(super::timestamp);
            match dts {
                Some(v) => parts.push(format!("seamless splice type {t}, DTS {}", seconds_90k(v))),
                None => parts.push(format!("seamless splice type {t}")),
            }
        }
        cx.emit(
            Node::new("Adaptation field extension")
                .span(ext)
                .summary(if parts.is_empty() {
                    format!("{} bytes", n.saturating_add(1))
                } else {
                    parts.join(", ")
                }),
        );
        at = at.saturating_add(1).saturating_add(n);
    }
    if at < end {
        cx.emit(
            Node::new("Stuffing")
                .span(span.sub(pos(at), pos(end.saturating_sub(at))))
                .summary(format!("{} bytes", end.saturating_sub(at))),
        );
    }
    Ok(())
}
