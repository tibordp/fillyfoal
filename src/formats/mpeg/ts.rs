//! MPEG-2 transport streams (ISO 13818-1): 188-byte packets, plus the
//! 192-byte BDAV/M2TS variant (4-byte timecode prefix) and 204-byte packets
//! with Reed-Solomon parity.
//!
//! The PAT and PMTs are read from the first packets to list programs and
//! their elementary streams; packets are listed in pages, each decoded on
//! expansion (header, adaptation field, PSI section or PES header).

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::vidutil::{self, enumerated, flag_node, hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::EnumTable;

use super::{pes_header, pes_summary};

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

pub const STREAM_TYPES: EnumTable = &[
    (0x01, "MPEG-1 video"),
    (0x02, "MPEG-2 video"),
    (0x03, "MPEG-1 audio"),
    (0x04, "MPEG-2 audio"),
    (0x05, "private sections"),
    (0x06, "PES private data"),
    (0x07, "MHEG"),
    (0x08, "DSM-CC"),
    (0x0b, "DSM-CC sections"),
    (0x0f, "AAC (ADTS)"),
    (0x10, "MPEG-4 Visual"),
    (0x11, "AAC (LATM)"),
    (0x12, "MPEG-4 SL"),
    (0x15, "metadata (PES)"),
    (0x1b, "H.264"),
    (0x1c, "MPEG-4 audio"),
    (0x20, "H.264 MVC"),
    (0x21, "JPEG 2000"),
    (0x24, "HEVC"),
    (0x2d, "MPEG-H 3D audio"),
    (0x33, "VVC"),
    (0x42, "AVS"),
    (0x80, "LPCM (Blu-ray)"),
    (0x81, "AC-3"),
    (0x82, "DTS"),
    (0x83, "TrueHD"),
    (0x84, "E-AC-3 (Blu-ray)"),
    (0x85, "DTS-HD HRA"),
    (0x86, "DTS-HD MA / SCTE-35"),
    (0x87, "E-AC-3"),
    (0x90, "PGS subtitles"),
    (0x92, "text subtitles"),
    (0xea, "VC-1"),
];

const TABLE_IDS: EnumTable = &[
    (0x00, "program association"),
    (0x01, "conditional access"),
    (0x02, "program map"),
    (0x03, "transport stream description"),
    (0x40, "network information (actual)"),
    (0x41, "network information (other)"),
    (0x42, "service description (actual)"),
    (0x46, "service description (other)"),
    (0x4e, "event information"),
    (0x70, "time and date"),
    (0x73, "time offset"),
    (0xfc, "SCTE-35 splice info"),
];

const ADAPTATION: EnumTable = &[
    (1, "payload only"),
    (2, "adaptation field only"),
    (3, "adaptation field and payload"),
];

const DESCRIPTORS: EnumTable = &[
    (0x02, "video stream"),
    (0x03, "audio stream"),
    (0x05, "registration"),
    (0x0a, "ISO 639 language"),
    (0x0e, "maximum bitrate"),
    (0x28, "AVC video"),
    (0x2a, "AVC timing and HRD"),
    (0x38, "HEVC video"),
    (0x48, "service"),
    (0x52, "stream identifier"),
    (0x56, "teletext"),
    (0x59, "subtitling"),
    (0x6a, "AC-3"),
    (0x7a, "E-AC-3"),
    (0x7b, "DTS"),
    (0x7c, "AAC"),
    (0x7f, "extension"),
];

#[derive(Clone, Debug)]
struct Stream {
    pid: u16,
    kind: u8,
    language: Option<String>,
    registration: Option<String>,
    span: Span,
}

impl Stream {
    fn codec(&self) -> String {
        match (self.kind, self.registration.as_deref()) {
            (0x06, Some("AC-3")) => "AC-3".to_owned(),
            (0x06, Some("EAC3")) => "E-AC-3".to_owned(),
            (0x06, Some("Opus")) => "Opus".to_owned(),
            (0x06, Some("HEVC")) => "HEVC".to_owned(),
            (0x06, Some("KLVA")) => "KLV metadata".to_owned(),
            _ => vidutil::lookup_or(STREAM_TYPES, self.kind.into()),
        }
    }
}

#[derive(Clone, Debug)]
struct Program {
    number: u16,
    pmt_pid: u16,
    pcr_pid: u16,
    streams: Vec<Stream>,
    /// Where the PMT section is.
    span: Option<Span>,
}

#[derive(Clone, Debug, Default)]
struct Psi {
    pat: Option<Span>,
    programs: Vec<Program>,
}

impl Psi {
    fn pid_name(&self, pid: u16) -> Option<String> {
        match pid {
            0 => return Some("PAT".to_owned()),
            1 => return Some("CAT".to_owned()),
            2 => return Some("TSDT".to_owned()),
            0x10 => return Some("NIT".to_owned()),
            0x11 => return Some("SDT".to_owned()),
            0x12 => return Some("EIT".to_owned()),
            0x14 => return Some("TDT/TOT".to_owned()),
            0x1fff => return Some("null".to_owned()),
            _ => {}
        }
        for p in &self.programs {
            if p.pmt_pid == pid {
                return Some(format!("PMT {}", p.number));
            }
            if let Some(s) = p.streams.iter().find(|s| s.pid == pid) {
                return Some(s.codec());
            }
        }
        None
    }

    fn is_psi(&self, pid: u16) -> bool {
        pid < 0x20 || self.programs.iter().any(|p| p.pmt_pid == pid)
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
}

const SCAN_PACKETS: u64 = 4096;
const PAGE: u64 = 64;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 2048)).await?;
    let probe = Head {
        data: &head,
        tail: &head,
        len: input.span.len,
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
    let psi = scan_psi(&cx, &ts).await?;
    ts.psi = Arc::new(psi);
    let duration = duration(&cx, &ts).await?;
    cx.annotate(summary(&ts, duration));

    let psi = ts.psi.clone();
    cx.emit(
        Node::new("Programs")
            .summary(vidutil::plural(to_u64(psi.programs.len()), "program"))
            .lazy(programs, ts.clone()),
    );
    let total = ts.layout.stride.saturating_mul(count);
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
    let streams: Vec<String> = ts
        .psi
        .programs
        .iter()
        .flat_map(|p| p.streams.iter().map(Stream::codec))
        .collect();
    if ts.psi.programs.len() > 1 {
        parts.push(vidutil::plural(to_u64(ts.psi.programs.len()), "program"));
    }
    if !streams.is_empty() {
        parts.push(streams.join(" + "));
    }
    if let Some(d) = duration {
        parts.push(vidutil::seconds_f64(d));
    }
    parts.push(vidutil::plural(ts.count, "packet"));
    parts.join(", ")
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

/// Reads the PAT and PMTs from the first packets.
async fn scan_psi(cx: &Cx, ts: &Ts) -> Result<Psi> {
    let mut psi = Psi::default();
    let limit = ts.count.min(SCAN_PACKETS);
    let mut wanted: Vec<u16> = Vec::new();
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
            let pid = pid_of(p);
            let Some((start, true)) = payload_start(p) else {
                continue;
            };
            let pointer = usize::from(*p.get(start).unwrap_or(&0));
            let sec = start.saturating_add(1).saturating_add(pointer);
            let Some(section) = p.get(sec..) else {
                continue;
            };
            let sec_len = section_body(section).len();
            let sec_span = page.sub(to_u64(at.saturating_add(sec)), to_u64(sec_len));
            if pid == 0 && psi.pat.is_none() && section.first() == Some(&0) {
                psi.pat = Some(sec_span);
                for (number, pmt_pid) in parse_pat(section) {
                    if number != 0 {
                        wanted.push(pmt_pid);
                        psi.programs.push(Program {
                            number,
                            pmt_pid,
                            pcr_pid: 0x1fff,
                            streams: Vec::new(),
                            span: None,
                        });
                    }
                }
            } else if wanted.contains(&pid) && section.first() == Some(&2) {
                wanted.retain(|&w| w != pid);
                let number = u16_be(section, 3).unwrap_or(0);
                if let Some(prog) = psi
                    .programs
                    .iter_mut()
                    .find(|p| p.pmt_pid == pid && p.number == number)
                {
                    prog.span = Some(sec_span);
                    parse_pmt(section, sec_span, prog);
                }
            }
        }
        if psi.pat.is_some() && wanted.is_empty() {
            break;
        }
        i = i.saturating_add(n);
    }
    Ok(psi)
}

/// Section length including the 3-byte header, clamped to the data.
fn section_body(section: &[u8]) -> &[u8] {
    let len = usize::from(u16_be(section, 1).unwrap_or(0) & 0x0fff);
    let end = len.saturating_add(3).min(section.len());
    section.get(..end).unwrap_or_default()
}

fn parse_pat(section: &[u8]) -> Vec<(u16, u16)> {
    let s = section_body(section);
    let end = s.len().saturating_sub(4);
    let mut out = Vec::new();
    let mut at = 8usize;
    while at.saturating_add(4) <= end {
        let number = u16_be(s, at).unwrap_or(0);
        let pid = u16_be(s, at.saturating_add(2)).unwrap_or(0) & 0x1fff;
        out.push((number, pid));
        at = at.saturating_add(4);
    }
    out
}

fn parse_pmt(section: &[u8], span: Span, prog: &mut Program) {
    let s = section_body(section);
    prog.pcr_pid = u16_be(s, 8).unwrap_or(0x1fff) & 0x1fff;
    let info_len = usize::from(u16_be(s, 10).unwrap_or(0) & 0x0fff);
    let end = s.len().saturating_sub(4);
    let mut at = 12usize.saturating_add(info_len);
    while at.saturating_add(5) <= end {
        let kind = s.get(at).copied().unwrap_or(0);
        let pid = u16_be(s, at.saturating_add(1)).unwrap_or(0) & 0x1fff;
        let es_len = usize::from(u16_be(s, at.saturating_add(3)).unwrap_or(0) & 0x0fff);
        let desc_start = at.saturating_add(5);
        let desc = s
            .get(desc_start..desc_start.saturating_add(es_len).min(end))
            .unwrap_or_default();
        let mut stream = Stream {
            pid,
            kind,
            language: None,
            registration: None,
            span: vidutil::at(span, at, 5usize.saturating_add(es_len)),
        };
        for (tag, body) in descriptors(desc) {
            match tag {
                0x0a => {
                    stream.language = body
                        .get(..3)
                        .map(|l| String::from_utf8_lossy(l).into_owned())
                }
                0x05 => {
                    stream.registration = body
                        .get(..4)
                        .map(|r| String::from_utf8_lossy(r).into_owned())
                }
                0x6a => stream.registration = Some("AC-3".to_owned()),
                0x7a => stream.registration = Some("EAC3".to_owned()),
                _ => {}
            }
        }
        prog.streams.push(stream);
        at = desc_start.saturating_add(es_len);
    }
}

fn descriptors(d: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let tag = *d.get(at)?;
        let len = usize::from(*d.get(at.checked_add(1)?)?);
        let start = at.checked_add(2)?;
        let body = d.get(start..start.checked_add(len)?)?;
        at = start.checked_add(len)?;
        Some((tag, body))
    })
}

/// Duration from the first and last PCR of the first program's PCR PID.
async fn duration(cx: &Cx, ts: &Ts) -> Result<Option<f64>> {
    let Some(pid) = ts.psi.programs.first().map(|p| p.pcr_pid) else {
        return Ok(None);
    };
    let window = ts.count.min(256);
    let first = find_pcr(cx, ts, pid, 0, window, false).await?;
    let last = find_pcr(cx, ts, pid, ts.count.saturating_sub(window), window, true).await?;
    Ok(match (first, last) {
        (Some(a), Some(b)) if b > a => Some(b.saturating_sub(a) as f64 / 27_000_000.0),
        _ => None,
    })
}

async fn find_pcr(
    cx: &Cx,
    ts: &Ts,
    pid: u16,
    from: u64,
    n: u64,
    last: bool,
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
        if pid_of(p) == pid
            && let Some(pcr) = pcr(p)
        {
            found = Some(pcr);
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
    let b = |i: usize| p.get(i).copied().map(u64::from);
    let base = b(6)? << 25 | b(7)? << 17 | b(8)? << 9 | b(9)? << 1 | b(10)? >> 7;
    let ext = (b(10)? & 1) << 8 | b(11)?;
    base.checked_mul(300)?.checked_add(ext)
}

async fn programs(cx: Cx, ts: Ts) -> Result<()> {
    if let Some(pat) = ts.psi.pat {
        cx.emit(
            Node::new("Program association table")
                .span(pat)
                .lazy(section, pat),
        );
    }
    for (i, p) in ts.psi.programs.iter().enumerate() {
        let mut node = Node::new(format!("Program {}", p.number)).summary(format!(
            "PMT PID {:#06x}, PCR PID {:#06x}, {}",
            p.pmt_pid,
            p.pcr_pid,
            vidutil::plural(to_u64(p.streams.len()), "stream")
        ));
        if let Some(span) = p.span {
            node = node.span(span);
        }
        cx.push(node.lazy(program, (ts.clone(), i))).await;
    }
    Ok(())
}

async fn program(cx: Cx, (ts, index): (Ts, usize)) -> Result<()> {
    let Some(p) = ts.psi.programs.get(index) else {
        return Ok(());
    };
    if let Some(span) = p.span {
        cx.emit(
            Node::new("Program map table")
                .span(span)
                .lazy(section, span),
        );
    }
    for s in &p.streams {
        let mut extras = Vec::new();
        if s.codec() != vidutil::lookup_or(STREAM_TYPES, s.kind.into()) {
            extras.push(s.codec());
        }
        if let Some(l) = &s.language {
            extras.push(format!("language {l}"));
        }
        if let Some(r) = &s.registration {
            extras.push(format!("registration {r}"));
        }
        let mut node = Node::new(format!("PID {:#06x}", s.pid)).span(s.span).value(
            crate::value::Value::Enum {
                raw: s.kind.into(),
                bits: 8,
                name: crate::value::lookup(STREAM_TYPES, s.kind.into()),
            },
        );
        if !extras.is_empty() {
            node = node.summary(extras.join(", "));
        }
        cx.emit(node);
    }
    Ok(())
}

/// Decodes a PSI section (PAT, PMT or other table header).
async fn section(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 1024)).await?;
    let s = section_body(&d);
    let table = s.first().copied().unwrap_or(0xff);
    cx.emit(enumerated(
        "Table ID",
        span.sub(0, 1),
        table.into(),
        8,
        TABLE_IDS,
    ));
    let word = u16_be(s, 1).unwrap_or(0);
    let s12 = span.sub(1, 2);
    cx.emit(flag_node(
        "Section syntax indicator",
        s12,
        word & 0x8000 != 0,
    ));
    cx.emit(uint("Section length", s12, (word & 0x0fff).into(), 12));
    if word & 0x8000 == 0 || s.len() < 8 {
        cx.emit(Node::new("Data").span(span.tail(3)));
        return Ok(());
    }
    cx.emit(uint(
        if table == 2 {
            "Program number"
        } else {
            "Table ID extension"
        },
        span.sub(3, 2),
        u16_be(s, 3).unwrap_or(0).into(),
        16,
    ));
    let b5 = s.get(5).copied().unwrap_or(0);
    cx.emit(uint(
        "Version",
        span.sub(5, 1),
        ((b5 >> 1) & 0x1f).into(),
        5,
    ));
    cx.emit(flag_node("Current/next", span.sub(5, 1), b5 & 1 != 0));
    cx.emit(uint(
        "Section number",
        span.sub(6, 1),
        s.get(6).copied().unwrap_or(0).into(),
        8,
    ));
    cx.emit(uint(
        "Last section number",
        span.sub(7, 1),
        s.get(7).copied().unwrap_or(0).into(),
        8,
    ));
    let end = s.len().saturating_sub(4);
    match table {
        0 => {
            let mut at = 8usize;
            while at.saturating_add(4) <= end {
                let number = u16_be(s, at).unwrap_or(0);
                let pid = u16_be(s, at.saturating_add(2)).unwrap_or(0) & 0x1fff;
                let name = if number == 0 {
                    "Network PID".to_owned()
                } else {
                    format!("Program {number}")
                };
                cx.emit(
                    hex(name, vidutil::at(span, at, 4), pid.into(), 13).summary(if number == 0 {
                        "NIT"
                    } else {
                        "PMT PID"
                    }),
                );
                at = at.saturating_add(4);
            }
        }
        2 => {
            cx.emit(hex(
                "PCR PID",
                span.sub(8, 2),
                (u16_be(s, 8).unwrap_or(0) & 0x1fff).into(),
                13,
            ));
            let info = u16_be(s, 10).unwrap_or(0) & 0x0fff;
            cx.emit(uint(
                "Program info length",
                span.sub(10, 2),
                info.into(),
                12,
            ));
            let info_end = 12usize.saturating_add(usize::from(info)).min(end);
            emit_descriptors(&cx, span, 12, s.get(12..info_end).unwrap_or_default());
            let mut at = info_end;
            while at.saturating_add(5) <= end {
                let kind = s.get(at).copied().unwrap_or(0);
                let pid = u16_be(s, at.saturating_add(1)).unwrap_or(0) & 0x1fff;
                let es_len = usize::from(u16_be(s, at.saturating_add(3)).unwrap_or(0) & 0x0fff);
                let total = 5usize.saturating_add(es_len);
                cx.emit(
                    enumerated(
                        format!("Stream PID {pid:#06x}"),
                        vidutil::at(span, at, total),
                        kind.into(),
                        8,
                        STREAM_TYPES,
                    )
                    .summary(format!("{} bytes of descriptors", es_len)),
                );
                let ds = at.saturating_add(5);
                emit_descriptors(
                    &cx,
                    span,
                    ds,
                    s.get(ds..ds.saturating_add(es_len).min(end))
                        .unwrap_or_default(),
                );
                at = ds.saturating_add(es_len);
            }
        }
        _ => cx.emit(Node::new("Table data").span(vidutil::at(span, 8, end.saturating_sub(8)))),
    }
    if let Some(crc) = u32_be(s, end) {
        let computed = mpeg_crc32(s.get(..end).unwrap_or_default());
        let mut node = hex("CRC-32", vidutil::at(span, end, 4), crc.into(), 32);
        node = if computed == crc {
            node.summary("valid")
        } else {
            node.diag(crate::error::Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#010x}"
            )))
        };
        cx.emit(node);
    }
    Ok(())
}

fn emit_descriptors(cx: &Cx, span: Span, base: usize, d: &[u8]) {
    let mut at = 0usize;
    for (tag, body) in descriptors(d) {
        let total = body.len().saturating_add(2);
        let mut node = enumerated(
            "Descriptor",
            vidutil::at(span, base.saturating_add(at), total),
            tag.into(),
            8,
            DESCRIPTORS,
        );
        node = match tag {
            0x0a => node
                .summary(String::from_utf8_lossy(body.get(..3).unwrap_or_default()).into_owned()),
            0x05 => node.summary(vidutil::fourcc(body.get(..4).unwrap_or_default())),
            _ => node.summary(format!("{} bytes", body.len())),
        };
        cx.emit(node);
        at = at.saturating_add(total);
    }
}

/// CRC-32/MPEG-2 (polynomial 0x04c11db7, no reflection, no final xor).
fn mpeg_crc32(data: &[u8]) -> u32 {
    u32::try_from(crate::codec::crc::CRC32_MPEG2.checksum(data)).unwrap_or(0)
}

async fn packets(cx: Cx, ts: Ts) -> Result<()> {
    cx.set_count(Count::Exact(ts.count));
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
            let at = vidutil::us(j.saturating_mul(stride));
            let raw = data
                .get(at..at.saturating_add(vidutil::us(stride)))
                .unwrap_or_default();
            let index = i.saturating_add(j);
            let span = ts.packet(index);
            let p = raw.get(vidutil::us(ts.layout.prefix)..).unwrap_or_default();
            cx.push(
                Node::new(format!("Packet {index}"))
                    .span(span)
                    .summary(packet_summary(&ts.psi, p))
                    .lazy(packet, (ts.clone(), index)),
            )
            .await;
        }
        i = i.saturating_add(n);
    }
    Ok(())
}

fn packet_summary(psi: &Psi, p: &[u8]) -> String {
    if p.first() != Some(&0x47) {
        return "lost sync".to_owned();
    }
    let pid = pid_of(p);
    let mut s = format!("PID {pid:#06x}");
    if let Some(name) = psi.pid_name(pid) {
        s = format!("{s} ({name})");
    }
    if let Some((start, true)) = payload_start(p) {
        let payload = p.get(start..).unwrap_or_default();
        if payload.starts_with(&[0, 0, 1]) {
            s = format!("{s}, {}", pes_summary(payload));
        } else if psi.is_psi(pid) {
            let pointer = usize::from(payload.first().copied().unwrap_or(0));
            let table = payload
                .get(pointer.saturating_add(1))
                .copied()
                .unwrap_or(0xff);
            s = format!(
                "{s}, {} section",
                vidutil::lookup_or(TABLE_IDS, table.into())
            );
        } else {
            s.push_str(", unit start");
        }
    }
    if pcr(p).is_some() {
        s.push_str(", PCR");
    }
    s
}

async fn packet(cx: Cx, (ts, index): (Ts, u64)) -> Result<()> {
    let whole = ts.packet(index);
    let data = cx.read_avail(whole).await?;
    if ts.layout.prefix == 4 {
        let tc = u32_be(&data, 0).unwrap_or(0);
        cx.emit(uint(
            "Copy permission",
            whole.sub(0, 4),
            (tc >> 30).into(),
            2,
        ));
        cx.emit(uint(
            "Arrival timestamp",
            whole.sub(0, 4),
            (tc & 0x3fff_ffff).into(),
            30,
        ));
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
    if let Some(name) = ts.psi.pid_name(pid) {
        pid_node = pid_node.summary(name);
    }
    cx.emit(pid_node);
    let b3 = p.get(3).copied().unwrap_or(0);
    let s3 = span.sub(3, 1);
    cx.emit(uint("Scrambling control", s3, (b3 >> 6).into(), 2));
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
        let summary = pcr(p).map(|v| format!("PCR {:.6} s", v as f64 / 27_000_000.0));
        let mut node = Node::new("Adaptation field").span(af).lazy(adaptation, af);
        if let Some(s) = summary {
            node = node.summary(s);
        }
        cx.emit(node);
        at = at.saturating_add(1).saturating_add(len);
    }
    if b3 & 0x10 == 0 || at >= p.len() {
        return Ok(());
    }
    let payload_span = vidutil::at(span, at, p.len().saturating_sub(at));
    let payload = p.get(at..).unwrap_or_default();
    if w & 0x4000 != 0 && payload.starts_with(&[0, 0, 1]) {
        let (header, _) = pes_header_len(payload);
        let head = payload_span.sub(0, header);
        cx.emit(
            Node::new("PES header")
                .span(head)
                .summary(pes_summary(payload))
                .lazy(pes, head),
        );
        cx.emit(Node::new("PES payload").span(payload_span.tail(header)));
    } else if w & 0x4000 != 0 && ts.psi.is_psi(pid) {
        let pointer = u64::from(payload.first().copied().unwrap_or(0));
        cx.emit(uint("Pointer field", payload_span.sub(0, 1), pointer, 8));
        let body = payload
            .get(vidutil::us(pointer.saturating_add(1))..)
            .unwrap_or_default();
        let sec = payload_span.sub(pointer.saturating_add(1), to_u64(section_body(body).len()));
        let table = body.first().copied().unwrap_or(0xff);
        if table == 0xff {
            cx.emit(Node::new("Stuffing").span(sec));
        } else {
            cx.emit(
                Node::new("Section")
                    .span(sec)
                    .summary(vidutil::lookup_or(TABLE_IDS, table.into()))
                    .lazy(section, sec),
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

fn pes_header_len(d: &[u8]) -> (u64, u16) {
    let id = d.get(3).copied().unwrap_or(0);
    let len = u16_be(d, 4).unwrap_or(0);
    if super::has_optional_header(id) && d.get(6).is_some_and(|b| b & 0xc0 == 0x80) {
        (
            9u64.saturating_add(d.get(8).copied().unwrap_or(0).into()),
            len,
        )
    } else {
        (6, len)
    }
}

async fn pes(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 64)).await?;
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
    cx.emit(
        Node::new("Flags")
            .span(span.sub(1, 1))
            .value(crate::value::Value::Flags {
                raw: flags.into(),
                bits: 8,
                set,
                unknown: 0,
            }),
    );
    let mut at = 2u64;
    // `pcr` expects the packet layout: pad a fake 4-byte header.
    let mut fake = vec![0x47, 0, 0, 0x20];
    fake.extend_from_slice(&d);
    if flags & 0x10 != 0 {
        if let Some(v) = pcr(&fake) {
            cx.emit(
                uint("PCR", span.sub(at, 6), v, 42)
                    .summary(format!("{:.6} s", v as f64 / 27_000_000.0)),
            );
        }
        at = at.saturating_add(6);
    }
    if flags & 0x08 != 0 {
        cx.emit(Node::new("OPCR").span(span.sub(at, 6)));
        at = at.saturating_add(6);
    }
    if flags & 0x04 != 0 {
        cx.emit(uint(
            "Splice countdown",
            span.sub(at, 1),
            d.get(vidutil::us(at)).copied().unwrap_or(0).into(),
            8,
        ));
        at = at.saturating_add(1);
    }
    let rest = span.tail(at);
    if !rest.is_empty() {
        cx.emit(Node::new("Remaining fields / stuffing").span(rest));
    }
    Ok(())
}
