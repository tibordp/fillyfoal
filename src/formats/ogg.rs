//! Ogg: a sequence of pages (`OggS`, flags, granule position, serial, page
//! sequence, CRC, segment table) carrying the packets of one or more
//! logical streams.
//!
//! Pages are listed lazily. The codec of each stream is identified from its
//! first packet; the identification and comment headers of Vorbis, Opus,
//! FLAC, Theora and Speex, and Skeleton headers, are decoded. A header
//! packet that continues on later pages is reassembled into a derived
//! source. The duration comes from the granule position of the last page.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::sound::{Bits, duration, leaf, u24};
use crate::formats::{Format, Head, Input, Probe, flac, vorbis};
use crate::node::Node;
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

/// The first packet of the first page, if this is an Ogg file.
fn first_packet<'a>(h: &'a Head<'_>) -> Option<&'a [u8]> {
    if !h.starts_with(b"OggS") || h.data.get(4) != Some(&0) {
        return None;
    }
    let segments = usize::from(*h.data.get(26)?);
    h.data.get(27usize.saturating_add(segments)..)
}

macro_rules! ogg_format {
    ($id:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $magic:literal) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom(|h| first_packet(h).is_some_and(|p| p.starts_with($magic))),
            dissect: crate::expander!(dissect: Input),
        };
    };
}

ogg_format!(
    OPUS,
    "opus",
    "Ogg Opus",
    ["opus", "ogg", "oga"],
    "audio/ogg; codecs=opus",
    b"OpusHead"
);
ogg_format!(
    OGG_FLAC,
    "ogg-flac",
    "Ogg FLAC",
    ["oga", "ogg"],
    "audio/ogg; codecs=flac",
    b"\x7fFLAC"
);
ogg_format!(
    SPEEX,
    "speex",
    "Ogg Speex",
    ["spx", "ogg"],
    "audio/ogg; codecs=speex",
    b"Speex   "
);
ogg_format!(
    THEORA,
    "theora",
    "Ogg Theora",
    ["ogv", "ogg"],
    "video/ogg",
    b"\x80theora"
);

/// Ogg Vorbis and any other Ogg stream.
pub static FORMAT: Format = Format {
    name: "ogg",
    title: "Ogg (Vorbis and other codecs)",
    extensions: &["ogg", "oga", "ogv", "ogx"],
    mime: "audio/ogg",
    probe: Probe::Custom(|h| first_packet(h).is_some()),
    dissect: crate::expander!(dissect: Input),
};

// ---------------------------------------------------------------------------
// Pages

const PAGE_FLAGS: FlagTable = &[flag(0x1, "CONTINUED"), flag(0x2, "BOS"), flag(0x4, "EOS")];

record! {
    pub struct PageHeader {
        magic: ascii[4] "Capture pattern",
        version: u8 "Version",
        flags: u8 "Header type" .flags(PAGE_FLAGS),
        granule: u64 "Granule position" .desc("Codec-defined position at the end of the last completed packet") .with(|&g, n| if g == u64::MAX { n.summary("-1: no packet ends on this page") } else { n }),
        serial: u32 "Stream serial number" .hex(),
        sequence: u32 "Page sequence number",
        crc: u32 "CRC" .hex(),
        segments: u8 "Segments",
    }
}

/// A page, located.
#[derive(Clone, Debug)]
struct Page {
    header: PageHeader,
    lacing: Vec<u8>,
    /// The whole page.
    span: Span,
    /// The packet data after the segment table.
    data: Span,
}

impl Page {
    /// `(offset in data, length, complete)` for each packet piece.
    fn packets(&self) -> Vec<(u64, u64, bool)> {
        let mut out = Vec::new();
        let mut start = 0u64;
        let mut len = 0u64;
        for &l in &self.lacing {
            len = len.saturating_add(l.into());
            if l < 255 {
                out.push((start, len, true));
                start = start.saturating_add(len);
                len = 0;
            }
        }
        if len > 0 || self.lacing.last() == Some(&255) {
            out.push((start, len, false));
        }
        out
    }
}

async fn read_page(cx: &Cx, file: Span, pos: u64) -> Result<Page> {
    let head_span = file.sub(pos, PageHeader::SIZE);
    let header = crate::fields::parse(cx, head_span, LE, &(), PageHeader::layout).await?;
    if header.magic != "OggS" {
        return Err(Diagnostic::malformed("expected an OggS capture pattern").at(head_span));
    }
    let lacing_span = file.sub(pos.saturating_add(PageHeader::SIZE), header.segments.into());
    let lacing = cx.read(lacing_span).await?;
    let body: u64 = lacing.iter().map(|&l| u64::from(l)).sum();
    let header_len = PageHeader::SIZE.saturating_add(header.segments.into());
    let span = file.sub(pos, header_len.saturating_add(body));
    let data = span.tail(header_len);
    Ok(Page {
        header,
        lacing,
        span,
        data,
    })
}

/// Ogg's CRC-32 (polynomial 0x04c11db7, not reflected), over the page with
/// the CRC field zeroed.
fn crc32(data: &[u8]) -> u32 {
    use crate::codec::crc::CRC32_OGG;
    let crc = data.iter().enumerate().fold(CRC32_OGG.init(), |crc, (i, &b)| {
        CRC32_OGG.update_byte(crc, if (22..26).contains(&i) { 0 } else { b })
    });
    u32::try_from(CRC32_OGG.finish(crc)).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Codecs

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Codec {
    Vorbis,
    Opus,
    Flac,
    Theora,
    Speex,
    Skeleton,
    Other,
}

impl Codec {
    fn of(packet: &[u8]) -> Codec {
        if packet.starts_with(b"\x01vorbis") {
            Codec::Vorbis
        } else if packet.starts_with(b"OpusHead") {
            Codec::Opus
        } else if packet.starts_with(b"\x7fFLAC") {
            Codec::Flac
        } else if packet.starts_with(b"\x80theora") {
            Codec::Theora
        } else if packet.starts_with(b"Speex   ") {
            Codec::Speex
        } else if packet.starts_with(b"fishead\0") {
            Codec::Skeleton
        } else {
            Codec::Other
        }
    }

    fn name(self) -> &'static str {
        match self {
            Codec::Vorbis => "Vorbis",
            Codec::Opus => "Opus",
            Codec::Flac => "FLAC",
            Codec::Theora => "Theora",
            Codec::Speex => "Speex",
            Codec::Skeleton => "Skeleton",
            Codec::Other => "unknown codec",
        }
    }
}

/// What the file summary needs about one logical stream.
#[derive(Clone, Debug)]
struct Stream {
    serial: u32,
    codec: Codec,
    /// Samples (or frames, for Theora) per second.
    rate: f64,
    channels: u64,
    /// Opus pre-skip; Theora granule shift.
    skip: u64,
    describe: String,
}

impl Stream {
    fn from_header(serial: u32, p: &[u8]) -> Stream {
        let codec = Codec::of(p);
        let mut s = Stream {
            serial,
            codec,
            rate: 0.0,
            channels: 0,
            skip: 0,
            describe: codec.name().to_owned(),
        };
        match codec {
            Codec::Vorbis => {
                s.channels = p.get(11).copied().unwrap_or(0).into();
                s.rate = f64::from(u32_le(p, 12).unwrap_or(0));
            }
            Codec::Opus => {
                s.channels = p.get(9).copied().unwrap_or(0).into();
                s.skip = u16_le(p, 10).unwrap_or(0).into();
                s.rate = 48000.0;
                let input = u32_le(p, 12).unwrap_or(0);
                s.describe = format!("Opus (input {input} Hz)");
            }
            Codec::Flac => {
                // "\x7fFLAC", 2 version bytes, 2 header count, "fLaC", block
                // header (4), then STREAMINFO.
                let info = p.get(17..).unwrap_or_default();
                let rate = crate::bytes::u24_be(info, 10).unwrap_or(0) >> 4;
                s.rate = f64::from(rate);
                s.channels = info
                    .get(12)
                    .map_or(0, |b| u64::from((b >> 1) & 7).saturating_add(1));
            }
            Codec::Theora => {
                let num = crate::bytes::u32_be(p, 22).unwrap_or(0);
                let den = crate::bytes::u32_be(p, 26).unwrap_or(0);
                if den > 0 {
                    s.rate = f64::from(num) / f64::from(den);
                }
                let w = crate::bytes::u24_be(p, 14).unwrap_or(0);
                let h = crate::bytes::u24_be(p, 17).unwrap_or(0);
                let shift = crate::bytes::u16_be(p, 40).map_or(0, |v| (v >> 5) & 0x1f);
                s.skip = shift.into();
                s.describe = format!("Theora {w}×{h}, {:.2} fps", s.rate);
            }
            Codec::Speex => {
                s.rate = f64::from(u32_le(p, 36).unwrap_or(0));
                s.channels = u32_le(p, 48).unwrap_or(0).into();
            }
            _ => {}
        }
        if matches!(
            codec,
            Codec::Vorbis | Codec::Opus | Codec::Flac | Codec::Speex
        ) {
            s.describe = format!(
                "{}, {} Hz, {} ch",
                if codec == Codec::Opus {
                    "Opus"
                } else {
                    codec.name()
                },
                s.rate as u64,
                s.channels
            );
        }
        s
    }

    fn is_audio(&self) -> bool {
        matches!(
            self.codec,
            Codec::Vorbis | Codec::Opus | Codec::Flac | Codec::Speex
        )
    }

    fn seconds(&self, granule: u64) -> Option<f64> {
        if self.rate <= 0.0 || granule == u64::MAX {
            return None;
        }
        let units = match self.codec {
            Codec::Opus => granule.saturating_sub(self.skip),
            Codec::Theora => {
                let shift = u32::try_from(self.skip).unwrap_or(0).min(63);
                let mask = (1u64 << shift).saturating_sub(1);
                (granule >> shift).saturating_add(granule & mask)
            }
            _ => granule,
        };
        Some(units as f64 / self.rate)
    }
}

type Streams = Arc<Vec<Stream>>;

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // Beginning-of-stream pages come first, one per logical stream.
    let mut streams = Vec::new();
    let mut pos = 0u64;
    while streams.len() < 32 {
        let Ok(page) = read_page(&cx, file, pos).await else {
            break;
        };
        if page.header.flags & 0x2 == 0 {
            break;
        }
        let first = cx.read_avail(page.data.sub(0, 64)).await?;
        streams.push(Stream::from_header(page.header.serial, &first));
        pos = pos.saturating_add(page.span.len.max(1));
    }
    let title = comment_title(&cx, file, pos, streams.first()).await;
    let streams: Streams = Arc::new(streams);
    let last = last_granules(&cx, file).await?;
    cx.annotate(describe(&streams, &last, title));

    cx.emit(
        Node::new("Pages")
            .span(file)
            .summary(format!("{} streams", streams.len()))
            .lazy(list_pages, (input, streams)),
    );
    Ok(())
}

fn describe(streams: &[Stream], last: &[(u32, u64)], title: Option<String>) -> String {
    let main = streams
        .iter()
        .find(|s| s.is_audio())
        .or_else(|| streams.first());
    let mut line = match (streams, main) {
        ([only], _) => format!("Ogg {}", only.describe),
        (_, Some(_)) => format!(
            "Ogg: {}",
            streams
                .iter()
                .filter(|s| s.codec != Codec::Skeleton)
                .map(|s| s.describe.clone())
                .collect::<Vec<_>>()
                .join("; ")
        ),
        _ => "Ogg".to_owned(),
    };
    if let Some(main) = main
        && let Some((_, g)) = last.iter().find(|(s, _)| *s == main.serial)
        && let Some(seconds) = main.seconds(*g)
    {
        line.push_str(&format!(", {}", duration(seconds)));
    }
    if let Some(t) = title {
        line.push_str(&format!(" — {t}"));
    }
    line
}

/// The comment header of the first stream, usually the first packet of the
/// page after the BOS pages.
async fn comment_title(cx: &Cx, file: Span, pos: u64, stream: Option<&Stream>) -> Option<String> {
    let stream = stream?;
    let page = read_page(cx, file, pos).await.ok()?;
    if page.header.serial != stream.serial {
        return None;
    }
    let skip = match stream.codec {
        Codec::Vorbis => 7,
        Codec::Opus => 8,
        Codec::Theora => 7,
        Codec::Speex => 0,
        Codec::Flac => 4,
        _ => return None,
    };
    vorbis::title(cx, page.data.tail(skip)).await
}

/// The last granule position of each stream, from the pages in the last
/// 64 KiB.
async fn last_granules(cx: &Cx, file: Span) -> Result<Vec<(u32, u64)>> {
    let start = file.len.saturating_sub(0x10000);
    let tail = cx.read_avail(file.tail(start)).await?;
    let mut out: Vec<(u32, u64)> = Vec::new();
    let mut i = 0usize;
    while let Some(at) = tail
        .get(i..)
        .and_then(|t| t.windows(4).position(|w| w == b"OggS"))
    {
        let p = i.saturating_add(at);
        if let (Some(g), Some(serial)) = (
            u64_le(&tail, p.saturating_add(6)),
            u32_le(&tail, p.saturating_add(14)),
        ) && g != u64::MAX
        {
            match out.iter_mut().find(|(s, _)| *s == serial) {
                Some(entry) => entry.1 = g,
                None => out.push((serial, g)),
            }
        }
        i = p.saturating_add(4);
    }
    Ok(out)
}

async fn list_pages(cx: Cx, (input, streams): (Input, Streams)) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < file.len {
        let page = match read_page(&cx, file, pos).await {
            Ok(p) => p,
            Err(e) => {
                cx.emit(Node::new("Unparsed data").span(file.tail(pos)).diag(e));
                return Ok(());
            }
        };
        let h = &page.header;
        let packets = page.packets();
        let complete = packets.iter().filter(|p| p.2).count();
        let mut summary = format!(
            "serial {:#x}, seq {}, granule {}, {complete} packets",
            h.serial,
            h.sequence,
            if h.granule == u64::MAX {
                "-1".to_owned()
            } else {
                h.granule.to_string()
            }
        );
        for (bit, name) in [(1, "continued"), (2, "BOS"), (4, "EOS")] {
            if h.flags & bit != 0 {
                summary.push_str(&format!(", {name}"));
            }
        }
        if h.flags & 2 != 0
            && let Some(s) = streams.iter().find(|s| s.serial == h.serial)
        {
            summary.push_str(&format!(" ({})", s.codec.name()));
        }
        let mut node = Node::new(format!("Page {index}"))
            .span(page.span)
            .summary(summary);
        let declared = PageHeader::SIZE
            .saturating_add(h.segments.into())
            .saturating_add(page.lacing.iter().map(|&l| u64::from(l)).sum());
        if page.span.len < declared {
            node = node.diag(Diagnostic::truncated(
                Span::new(page.span.source, page.span.offset, declared),
                page.span.len,
            ));
        }
        let state = PageState {
            input,
            pos,
            streams: streams.clone(),
        };
        cx.push(node.lazy(expand_page, state)).await;
        pos = pos.saturating_add(page.span.len.max(1));
        index = index.saturating_add(1);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PageState {
    input: Input,
    /// Offset of the page in the file.
    pos: u64,
    streams: Streams,
}

async fn expand_page(cx: Cx, st: PageState) -> Result<()> {
    let file = st.input.span;
    let page = read_page(&cx, file, st.pos).await?;
    let header = page.span.sub(0, PageHeader::SIZE);
    let mut node = PageHeader::node("Header", header, LE);
    if page.span.len <= cx.limits().max_read {
        let bytes = cx.read_avail(page.span).await?;
        if to_u64(bytes.len()) == page.span.len {
            let computed = crc32(&bytes);
            node = if computed == page.header.crc {
                node.summary("CRC valid")
            } else {
                node.diag(Diagnostic::warning(format!(
                    "CRC mismatch: computed {computed:#010x}"
                )))
            };
        }
    }
    cx.emit(node);
    cx.emit(
        Node::new("Segment table")
            .span(page.span.sub(PageHeader::SIZE, page.header.segments.into()))
            .summary(format!("{} segments", page.header.segments))
            .desc("Lacing values: a packet ends at the first value below 255"),
    );
    let stream = st
        .streams
        .iter()
        .find(|s| s.serial == page.header.serial)
        .cloned();
    for (i, (offset, len, complete)) in page.packets().into_iter().enumerate() {
        let span = page.data.sub(offset, len);
        let continued = i == 0 && page.header.flags & 1 != 0;
        let head = cx.read_avail(span.sub(0, 16)).await?;
        let kind = if continued {
            None
        } else {
            header_kind(&head, stream.as_ref(), page.header.granule)
        };
        let mut name = format!("Packet {i}");
        let mut summary = format!("{len} bytes");
        if continued {
            summary.push_str(", continued from the previous page");
        }
        if !complete {
            summary.push_str(", continues on the next page");
        }
        if let Some(k) = kind {
            name = k.name().to_owned();
        }
        let mut node = Node::new(name).span(span).summary(summary);
        if let Some(k) = kind {
            node = node.lazy(
                expand_packet,
                PacketState {
                    input: st.input,
                    span,
                    page: st.pos,
                    serial: page.header.serial,
                    complete,
                    kind: k,
                },
            );
        }
        cx.emit(node);
        cx.checkpoint().await;
    }
    Ok(())
}

/// Codec header packets we decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    VorbisId,
    VorbisComment,
    VorbisSetup,
    OpusHead,
    OpusTags,
    FlacHead,
    FlacBlock,
    TheoraId,
    TheoraComment,
    TheoraSetup,
    SpeexHeader,
    SpeexComment,
    Fishead,
    Fisbone,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::VorbisId => "Vorbis identification header",
            Kind::VorbisComment => "Vorbis comment header",
            Kind::VorbisSetup => "Vorbis setup header",
            Kind::OpusHead => "Opus identification header",
            Kind::OpusTags => "Opus comment header",
            Kind::FlacHead => "FLAC mapping header",
            Kind::FlacBlock => "FLAC metadata block",
            Kind::TheoraId => "Theora identification header",
            Kind::TheoraComment => "Theora comment header",
            Kind::TheoraSetup => "Theora setup header",
            Kind::SpeexHeader => "Speex header",
            Kind::SpeexComment => "Speex comment header",
            Kind::Fishead => "Skeleton head",
            Kind::Fisbone => "Skeleton bone",
        }
    }
}

fn header_kind(p: &[u8], stream: Option<&Stream>, granule: u64) -> Option<Kind> {
    Some(match p {
        [1, b'v', b'o', b'r', b'b', b'i', b's', ..] => Kind::VorbisId,
        [3, b'v', b'o', b'r', b'b', b'i', b's', ..] => Kind::VorbisComment,
        [5, b'v', b'o', b'r', b'b', b'i', b's', ..] => Kind::VorbisSetup,
        [0x80, b't', b'h', b'e', b'o', b'r', b'a', ..] => Kind::TheoraId,
        [0x81, b't', b'h', b'e', b'o', b'r', b'a', ..] => Kind::TheoraComment,
        [0x82, b't', b'h', b'e', b'o', b'r', b'a', ..] => Kind::TheoraSetup,
        _ if p.starts_with(b"OpusHead") => Kind::OpusHead,
        _ if p.starts_with(b"OpusTags") => Kind::OpusTags,
        _ if p.starts_with(b"\x7fFLAC") => Kind::FlacHead,
        _ if p.starts_with(b"Speex   ") => Kind::SpeexHeader,
        _ if p.starts_with(b"fishead\0") => Kind::Fishead,
        _ if p.starts_with(b"fisbone\0") => Kind::Fisbone,
        [b, ..] if stream.is_some_and(|s| s.codec == Codec::Flac) && *b != 0xff && granule == 0 => {
            Kind::FlacBlock
        }
        [_, ..] if stream.is_some_and(|s| s.codec == Codec::Speex) && granule == 0 => {
            Kind::SpeexComment
        }
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug)]
struct PacketState {
    input: Input,
    span: Span,
    /// Offset of the page holding the packet's start.
    page: u64,
    serial: u32,
    complete: bool,
    kind: Kind,
}

/// The whole packet: its span, or a derived source reassembled from the
/// pages it spans.
async fn packet_span(cx: &Cx, st: &PacketState) -> Result<Span> {
    if st.complete {
        return Ok(st.span);
    }
    let origin = Origin {
        parent: st.span,
        transform: "ogg-packet",
    };
    if let Some(d) = cx.derived(origin) {
        return Ok(d.span);
    }
    let file = st.input.span;
    let mut data = cx.read(st.span).await?;
    let first = read_page(cx, file, st.page).await?;
    let mut pos = st.page.saturating_add(first.span.len.max(1));
    let mut pages = 0u32;
    let max = cx.limits().max_read;
    'pages: while pos < file.len && pages < 4096 {
        let page = read_page(cx, file, pos).await?;
        pos = pos.saturating_add(page.span.len.max(1));
        pages = pages.saturating_add(1);
        if page.header.serial != st.serial {
            continue;
        }
        let mut offset = 0u64;
        for &l in &page.lacing {
            let piece = cx.read(page.data.sub(offset, l.into())).await?;
            data.extend_from_slice(&piece);
            offset = offset.saturating_add(l.into());
            if to_u64(data.len()) > max {
                return Err(Diagnostic::limit("packet too large to reassemble").at(st.span));
            }
            if l < 255 {
                break 'pages;
            }
        }
    }
    let consumed = to_u64(data.len());
    Ok(cx.add_derived(origin, data, consumed, None)?.span)
}

async fn expand_packet(cx: Cx, st: PacketState) -> Result<()> {
    let span = packet_span(&cx, &st).await?;
    if span.source != st.span.source {
        cx.diag(Diagnostic::note("reassembled from several pages"));
    }
    let block = cx.block(span.sub(0, span.len.min(0x1000))).await?;
    match st.kind {
        Kind::VorbisId => {
            let mut f = Fields::emitting(&cx, &block, LE);
            f.bytes("Packet type and signature", 7).emit()?;
            f.u32("Vorbis version").emit()?;
            f.u8("Channels").emit()?;
            f.u32("Sample rate").emit()?;
            f.i32("Maximum bitrate").emit()?;
            f.i32("Nominal bitrate").emit()?;
            f.i32("Minimum bitrate").emit()?;
            f.u8("Block sizes")
                .with(|&v, n| {
                    n.summary(format!(
                        "{} / {}",
                        1u32 << (v & 0xf).min(31),
                        1u32 << (v >> 4).min(31)
                    ))
                })
                .emit()?;
            f.u8("Framing flag").emit()?;
        }
        Kind::VorbisComment | Kind::TheoraComment | Kind::OpusTags | Kind::SpeexComment => {
            let skip = match st.kind {
                Kind::OpusTags => 8,
                Kind::SpeexComment => 0,
                _ => 7,
            };
            if skip > 0 {
                cx.emit(Node::new("Signature").span(span.sub(0, skip)));
            }
            let used = vorbis::emit(&cx, span.tail(skip)).await?;
            let rest = span.tail(skip.saturating_add(used));
            if !rest.is_empty() {
                cx.emit(
                    Node::new("Trailing bytes")
                        .span(rest)
                        .desc("Framing bit or padding"),
                );
            }
        }
        Kind::OpusHead => {
            let mut f = Fields::emitting(&cx, &block, LE);
            f.ascii("Signature", 8).emit()?;
            f.u8("Version").emit()?;
            let channels = f.u8("Channels").emit()?;
            f.u16("Pre-skip")
                .desc("Samples (at 48 kHz) to discard")
                .emit()?;
            f.u32("Input sample rate").emit()?;
            f.int::<i16>("Output gain")
                .with(|&g, n| n.summary(format!("{:.2} dB", f64::from(g) / 256.0)))
                .emit()?;
            let family = f
                .u8("Channel mapping family")
                .enumeration(&[(0, "mono/stereo"), (1, "Vorbis order"), (255, "undefined")])
                .emit()?;
            if family != 0 {
                f.u8("Stream count").emit()?;
                f.u8("Coupled streams").emit()?;
                f.bytes("Channel mapping", channels.into()).emit()?;
            }
        }
        Kind::FlacHead => {
            let mut f = Fields::emitting(&cx, &block, BE);
            f.bytes("Signature", 5).emit()?;
            f.u8("Major version").emit()?;
            f.u8("Minor version").emit()?;
            f.u16("Header packets").desc("0 = unknown").emit()?;
            f.ascii("FLAC signature", 4).emit()?;
            cx.emit(flac::block_node(&cx, st.input, span.tail(13)).await?);
        }
        Kind::FlacBlock => cx.emit(flac::block_node(&cx, st.input, span).await?),
        Kind::TheoraId => {
            let mut f = Fields::emitting(&cx, &block, BE);
            f.bytes("Packet type and signature", 7).emit()?;
            f.u8("Major version").emit()?;
            f.u8("Minor version").emit()?;
            f.u8("Revision").emit()?;
            f.u16("Frame width (macroblocks)").emit()?;
            f.u16("Frame height (macroblocks)").emit()?;
            u24(&mut f, "Picture width", BE).emit()?;
            u24(&mut f, "Picture height", BE).emit()?;
            f.u8("Picture X offset").emit()?;
            f.u8("Picture Y offset").emit()?;
            let num = f.u32("Frame rate numerator").emit()?;
            f.u32("Frame rate denominator")
                .with(|&d, n| {
                    if d > 0 {
                        n.summary(format!("{:.3} fps", f64::from(num) / f64::from(d)))
                    } else {
                        n
                    }
                })
                .emit()?;
            u24(&mut f, "Aspect ratio numerator", BE).emit()?;
            u24(&mut f, "Aspect ratio denominator", BE).emit()?;
            f.u8("Color space")
                .enumeration(&[(0, "undefined"), (1, "Rec. 470M"), (2, "Rec. 470BG")])
                .emit()?;
            u24(&mut f, "Nominal bitrate", BE).emit()?;
            let at = f.pos();
            let data = block.data.get(to_usize(at)..).unwrap_or_default();
            let mut b = Bits::emitting(&cx, data, span.tail(at));
            b.field("Quality", 6).emit()?;
            b.field("Keyframe granule shift", 5).emit()?;
            b.field("Pixel format", 2)
                .enumeration(&[(0, "4:2:0"), (2, "4:2:2"), (3, "4:4:4")])
                .emit()?;
            b.field("Reserved", 3).emit()?;
        }
        Kind::SpeexHeader => {
            let mut f = Fields::emitting(&cx, &block, LE);
            f.ascii("Signature", 8).emit()?;
            f.ascii("Version", 20).emit()?;
            f.i32("Version ID").emit()?;
            f.i32("Header size").emit()?;
            f.i32("Sample rate").emit()?;
            f.i32("Mode")
                .with(|&m, n| {
                    n.summary(match m {
                        0 => "narrowband",
                        1 => "wideband",
                        2 => "ultra-wideband",
                        _ => "unknown",
                    })
                })
                .emit()?;
            f.i32("Mode bitstream version").emit()?;
            f.i32("Channels").emit()?;
            f.i32("Bitrate").emit()?;
            f.i32("Frame size").emit()?;
            f.i32("VBR").emit()?;
            f.i32("Frames per packet").emit()?;
            f.i32("Extra headers").emit()?;
            f.i32("Reserved").emit()?;
            f.i32("Reserved").emit()?;
        }
        Kind::Fishead => {
            let mut f = Fields::emitting(&cx, &block, LE);
            f.ascii("Identifier", 8).emit()?;
            f.u16("Major version").emit()?;
            f.u16("Minor version").emit()?;
            f.int::<i64>("Presentation time numerator").emit()?;
            f.int::<i64>("Presentation time denominator").emit()?;
            f.int::<i64>("Base time numerator").emit()?;
            f.int::<i64>("Base time denominator").emit()?;
            f.bytes("UTC", 20).emit()?;
        }
        Kind::Fisbone => {
            let mut f = Fields::emitting(&cx, &block, LE);
            f.ascii("Identifier", 8).emit()?;
            let offset = f.u32("Message header offset").emit()?;
            f.u32("Serial number").hex().emit()?;
            f.u32("Header packets").emit()?;
            f.int::<i64>("Granule rate numerator").emit()?;
            f.int::<i64>("Granule rate denominator").emit()?;
            f.int::<i64>("Base granule").emit()?;
            f.u32("Preroll").emit()?;
            f.u8("Granule shift").emit()?;
            let headers = span.tail(u64::from(offset).saturating_add(8));
            let text = cx.read_avail(headers.sub(0, 4096)).await?;
            cx.emit(leaf(
                "Message headers",
                headers,
                crate::formats::util::sound::text(String::from_utf8_lossy(&text).into_owned()),
            ));
        }
        Kind::VorbisSetup | Kind::TheoraSetup => {
            cx.emit(Node::new("Signature").span(span.sub(0, 7)));
            cx.emit(Node::new("Codebooks and modes").span(span.tail(7)));
        }
    }
    Ok(())
}
