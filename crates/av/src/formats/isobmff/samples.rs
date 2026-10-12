//! The samples of a track, located in the file from its sample table:
//! `stsc` maps samples to chunks, `stco`/`co64` give each chunk's file
//! offset, `stsz`/`stz2` each sample's size (ISO 14496-12 8.7). Listed
//! lazily in pages with resume marks; the tables are read a window at a
//! time, never whole. Video samples of AVC, HEVC, AV1 and VP9 tracks split
//! into NAL units, OBUs or the VP9 frame header ([`coded`]), also behind
//! `encv` when `sinf`/`frma` names the original format; 3GPP timed text
//! (`tx3g`) samples show their text.
//!
//! Fragmented files list the samples of each track run (`trun`) the same
//! way, located from the base data offset (`tfhd`), the run's data offset
//! and the per-sample or default sizes (`tfhd`, else `trex`).

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::formats::util::fmt::plural;
use crate::formats::util::vidutil::nal::NalCodec;
use crate::formats::video::coded;
use crate::node::Node;
use crate::span::Span;

use super::{find_child, read_header, small};

/// How sample sizes are stored.
#[derive(Clone, Copy, Debug)]
enum Sizes {
    /// Every sample has this size (`stsz` with a nonzero sample size).
    Fixed(u64),
    /// A table of `bits`-wide entries at `span` (`stsz`: 32, `stz2`: 4,
    /// 8 or 16).
    Table { span: Span, bits: u8 },
}

/// Where a track's sample table lives.
#[derive(Clone, Debug)]
struct Tables {
    /// The file the chunk offsets point into.
    file: Span,
    /// `stsc` entries and their count.
    stsc: Span,
    stsc_count: u64,
    sizes: Sizes,
    /// Number of samples (`stsz`/`stz2` sample count).
    samples: u64,
    /// Chunk offsets, 4 or 8 bytes each, and their count.
    offsets: Span,
    offsets_count: u64,
    wide: bool,
    /// Decoding per sample description (index - 1).
    configs: Arc<Vec<Decode>>,
}

/// How the samples of one sample description are decoded.
#[derive(Clone, Debug)]
enum Decode {
    /// Split into NAL units, OBUs or a VP9 frame header.
    Coded(Arc<coded::Config>),
    /// 3GPP timed text: a 16-bit length, then UTF-8 (or UTF-16) text.
    Tx3g,
    /// Protected (`encv`) AVC/HEVC: length-prefixed NAL units whose
    /// headers are clear (ISO 23001-7 subsample encryption) but whose
    /// payloads are not decoded.
    Protected(NalCodec, u64),
    None,
}

impl Decode {
    /// The sample's node, made expandable when there is something to show.
    fn apply(&self, node: Node, span: Span) -> Node {
        if span.is_empty() {
            return node;
        }
        match self {
            Decode::Coded(c) if c.splits() => node.lazy(
                coded::expand,
                coded::Frame {
                    span,
                    config: c.clone(),
                },
            ),
            Decode::Tx3g => node.lazy(tx3g_sample, span),
            Decode::Protected(codec, len) => node.lazy(protected_sample, (span, *codec, *len)),
            _ => node,
        }
    }
}

/// A protected AVC/HEVC sample: its NAL units by type, payloads left
/// encrypted.
async fn protected_sample(cx: Cx, (span, codec, size): (Span, NalCodec, u64)) -> Result<()> {
    let mut pos = 0u64;
    while pos < span.len {
        let d = cx.read_avail(span.sub(pos, size.saturating_add(1))).await?;
        let len = d
            .get(..crate::bytes::to_usize(size))
            .unwrap_or_default()
            .iter()
            .fold(0u64, |a, &b| a.wrapping_shl(8) | u64::from(b));
        let unit = span.sub(pos, size.saturating_add(len));
        let kind = d
            .get(crate::bytes::to_usize(size))
            .map(|&b| u64::from(codec.nal_type(b)));
        let name = kind.map_or_else(
            || "NAL unit".to_owned(),
            |t| crate::formats::util::vidutil::lookup_or(codec.types(), t),
        );
        let mut node = Node::new(name)
            .span(unit)
            .summary(format!("{len} bytes, payload encrypted"));
        if unit.len < size.saturating_add(len) {
            node = node.diag(Diagnostic::truncated(span.sub(pos, 0), unit.len));
        }
        cx.push(node).await;
        if len == 0 {
            break;
        }
        pos = pos.saturating_add(size).saturating_add(len);
    }
    Ok(())
}

/// A 3GPP timed text sample: `text_length`, the text, then modifier boxes.
async fn tx3g_sample(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 0x1_0000)).await?;
    let len = u16_be(&d, 0).unwrap_or(0);
    cx.emit(
        Node::new("Text length")
            .span(span.sub(0, 2))
            .value(crate::formats::util::val::uint(len, 16)),
    );
    let bytes = d
        .get(2..usize::from(len).saturating_add(2))
        .unwrap_or_default();
    let text = if bytes.starts_with(&[0xfe, 0xff]) {
        crate::text::utf16(
            bytes.get(2..).unwrap_or_default(),
            crate::bytes::Endian::Big,
        )
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    cx.emit(
        Node::new("Text")
            .span(span.sub(2, len.into()))
            .value(crate::formats::util::val::text(text)),
    );
    let rest = span.tail(u64::from(len).saturating_add(2));
    if rest.len > 0 {
        cx.emit(
            Node::new("Modifier boxes")
                .span(rest)
                .summary(format!("{} bytes", rest.len)),
        );
    }
    Ok(())
}

/// The walker's position: everything the loop carries, for resume marks.
#[derive(Clone, Copy, Debug, Default)]
struct Pos {
    /// 0-based index of the next sample.
    sample: u64,
    /// 1-based number of the current chunk (0 before the first).
    chunk: u64,
    /// Index of the `stsc` entry the current chunk belongs to.
    run: u64,
    /// Samples left in the current chunk.
    left: u64,
    /// Offset of the next sample in the file.
    offset: u64,
    /// 1-based sample description index of the current chunk.
    desc: u64,
}

/// Bytes per page of table reads.
const WINDOW: u64 = 4096;

/// Sample descriptions whose codec configuration is looked at.
const MAX_DESCRIPTIONS: u64 = 16;

/// A window over a table, refilled as reads move past it.
struct Window {
    span: Span,
    start: u64,
    data: Vec<u8>,
}

impl Window {
    fn new(span: Span) -> Window {
        Window {
            span,
            start: 0,
            data: Vec::new(),
        }
    }

    /// The `n` bytes at `at` (fewer at the end of the table).
    async fn get(&mut self, cx: &Cx, at: u64, n: u64) -> Result<&[u8]> {
        let end = at.saturating_add(n);
        let have = self.start.saturating_add(to_u64(self.data.len()));
        if at < self.start || end > have {
            self.start = at;
            self.data = cx.read(self.span.sub(at, WINDOW.max(n))).await?;
        }
        let from = crate::bytes::to_usize(at.saturating_sub(self.start));
        let to = crate::bytes::to_usize(end.saturating_sub(self.start)).min(self.data.len());
        Ok(self.data.get(from..to).unwrap_or_default())
    }
}

/// A lazy "Samples" node for the sample table whose `stbl` body is `stbl`,
/// or `None` when the table lacks the boxes needed to locate samples.
pub async fn node(cx: &Cx, input: Input, stbl: Span) -> Result<Option<Node>> {
    let body = async |kind: &[u8; 4]| -> Result<Option<Span>> {
        Ok(find_child(cx, stbl, kind)
            .await?
            .map(|(h, span)| span.tail(h.header_len)))
    };
    let Some(stsc) = body(b"stsc").await? else {
        return Ok(None);
    };
    let (offsets, wide) = match body(b"stco").await? {
        Some(s) => (s, false),
        None => match body(b"co64").await? {
            Some(s) => (s, true),
            None => return Ok(None),
        },
    };
    let (sizes, samples) = match body(b"stsz").await? {
        Some(s) => {
            let d = cx.read_avail(s.sub(0, 12)).await?;
            let size = u32_be(&d, 4).unwrap_or(0);
            let n = u64::from(u32_be(&d, 8).unwrap_or(0));
            if size == 0 {
                (
                    Sizes::Table {
                        span: s.tail(12),
                        bits: 32,
                    },
                    n,
                )
            } else {
                (Sizes::Fixed(size.into()), n)
            }
        }
        None => match body(b"stz2").await? {
            Some(s) => {
                let d = cx.read_avail(s.sub(0, 12)).await?;
                let bits = d.get(7).copied().unwrap_or(0);
                if !matches!(bits, 4 | 8 | 16) {
                    return Ok(None);
                }
                let n = u64::from(u32_be(&d, 8).unwrap_or(0));
                (
                    Sizes::Table {
                        span: s.tail(12),
                        bits,
                    },
                    n,
                )
            }
            None => return Ok(None),
        },
    };
    let count = |span: Span| async move {
        let d = cx.read_avail(span.sub(4, 4)).await?;
        Result::Ok(u64::from(u32_be(&d, 0).unwrap_or(0)))
    };
    let stsc_count = count(stsc).await?;
    let offsets_count = count(offsets).await?;
    if samples == 0 || stsc_count == 0 || offsets_count == 0 {
        return Ok(None);
    }
    let tables = Tables {
        file: input.span,
        stsc: stsc.tail(8),
        stsc_count,
        sizes,
        samples,
        offsets: offsets.tail(8),
        offsets_count,
        wide,
        configs: Arc::new(Vec::new()),
    };
    let summary = format!(
        "{} in {}",
        plural(samples, "sample"),
        plural(offsets_count, "chunk")
    );
    Ok(Some(
        Node::new("Samples")
            .summary(summary)
            .desc("Each sample's bytes, located through stsc, stco/co64 and stsz/stz2")
            .lazy(expand, (tables, stbl)),
    ))
}

/// Decoding for each sample description in `stsd` (at most
/// [`MAX_DESCRIPTIONS`]).
async fn configs(cx: &Cx, stbl: Span) -> Result<Vec<Decode>> {
    let mut out = Vec::new();
    let Some((h, stsd)) = find_child(cx, stbl, b"stsd").await? else {
        return Ok(out);
    };
    let entries = stsd.tail(h.header_len).tail(8);
    let mut pos = 0u64;
    while to_u64(out.len()) < MAX_DESCRIPTIONS {
        let Some(e) = read_header(cx, entries, pos).await? else {
            break;
        };
        let body = entries.sub(pos, e.size).tail(e.header_len);
        let mut fourcc = e.kind;
        let mut d = Vec::new();
        if &fourcc == b"encv" {
            // Protected video: the original format is in sinf/frma.
            d = small(cx, body).await?;
            let original = super::sample::child_boxes(&d, 78)
                .into_iter()
                .find(|(k, _)| k == b"sinf")
                .and_then(|(_, sinf)| {
                    super::sample::child_boxes(sinf, 0)
                        .into_iter()
                        .find(|(k, _)| k == b"frma")
                })
                .and_then(|(_, frma)| crate::bytes::array::<4>(frma, 0));
            if let Some(o) = original {
                fourcc = o;
            }
        }
        if &fourcc == b"tx3g" {
            out.push(Decode::Tx3g);
            pos = pos.saturating_add(e.size);
            if e.to_end {
                break;
            }
            continue;
        }
        let kind = coded::Kind::from_fourcc(&fourcc);
        let protected = &e.kind == b"encv";
        let mut config = coded::Config::bare(kind);
        if kind != coded::Kind::Other {
            if d.is_empty() {
                d = small(cx, body).await?;
            }
            let want: &[u8; 4] = match kind {
                coded::Kind::Avc => b"avcC",
                coded::Kind::Hevc => b"hvcC",
                coded::Kind::Av1 => b"av1C",
                _ => b"\0\0\0\0",
            };
            // Visual sample entries: 78 bytes of fields, then boxes.
            if let Some((_, record)) = super::sample::child_boxes(&d, 78)
                .into_iter()
                .find(|(k, _)| k == want)
            {
                config = coded::Config::from_record(kind, record);
            }
        }
        out.push(match (protected, kind) {
            (true, coded::Kind::Avc) => Decode::Protected(NalCodec::Avc, config.length_size),
            (true, coded::Kind::Hevc) => Decode::Protected(NalCodec::Hevc, config.length_size),
            (true, _) => Decode::None,
            _ => Decode::Coded(Arc::new(config)),
        });
        pos = pos.saturating_add(e.size);
        if e.to_end {
            break;
        }
    }
    Ok(out)
}

async fn expand(cx: Cx, (mut t, stbl): (Tables, Span)) -> Result<()> {
    t.configs = Arc::new(configs(&cx, stbl).await?);
    // Size tables shorter than their count limit it.
    let samples = match t.sizes {
        Sizes::Fixed(_) => t.samples,
        Sizes::Table { span, bits } => {
            let fits = span
                .len
                .saturating_mul(8)
                .checked_div(bits.into())
                .unwrap_or(0);
            if t.samples > fits {
                cx.diag(Diagnostic::malformed(format!(
                    "{} listed, sizes for only {fits}",
                    plural(t.samples, "sample")
                )));
            }
            t.samples.min(fits)
        }
    };
    // The chunks may hold fewer samples than the size table lists, so the
    // count is not announced; progress is.
    let mut stsc = Window::new(t.stsc);
    let mut sizes = Window::new(match t.sizes {
        Sizes::Table { span, .. } => span,
        Sizes::Fixed(_) => t.stsc.sub(0, 0),
    });
    let mut offsets = Window::new(t.offsets);
    let stride: u64 = if t.wide { 8 } else { 4 };
    let mut p = cx.resume::<Pos>().unwrap_or_default();
    while p.sample < samples {
        // Move to the next chunk that holds samples.
        while p.left == 0 {
            if p.chunk >= t.offsets_count {
                cx.diag(Diagnostic::malformed(format!(
                    "the chunks hold only {} of {}",
                    plural(p.sample, "sample"),
                    samples
                )));
                return Ok(());
            }
            p.chunk = p.chunk.saturating_add(1);
            // The stsc entry of this chunk: runs are in increasing order of
            // first chunk.
            while p.run.saturating_add(1) < t.stsc_count {
                let at = p.run.saturating_add(1).saturating_mul(12);
                let next = stsc.get(&cx, at, 4).await?;
                match u32_be(next, 0) {
                    Some(first) if u64::from(first) <= p.chunk => p.run = p.run.saturating_add(1),
                    _ => break,
                }
            }
            let e = stsc.get(&cx, p.run.saturating_mul(12), 12).await?;
            p.left = u64::from(u32_be(e, 4).unwrap_or(0));
            p.desc = u64::from(u32_be(e, 8).unwrap_or(0));
            let at = p.chunk.saturating_sub(1).saturating_mul(stride);
            let o = offsets.get(&cx, at, stride).await?;
            p.offset = if t.wide {
                u64_be(o, 0)
            } else {
                u32_be(o, 0).map(u64::from)
            }
            .unwrap_or(0);
            cx.checkpoint().await;
        }
        let size = match t.sizes {
            Sizes::Fixed(s) => s,
            Sizes::Table { bits, .. } => {
                let bit = p.sample.saturating_mul(bits.into());
                let n = u64::from(bits.div_ceil(8));
                let d = sizes.get(&cx, bit / 8, n).await?;
                match bits {
                    4 => {
                        let b = d.first().copied().unwrap_or(0);
                        u64::from(if bit % 8 == 0 { b >> 4 } else { b & 15 })
                    }
                    8 => d.first().copied().map_or(0, u64::from),
                    16 => u16_be(d, 0).map_or(0, u64::from),
                    _ => u32_be(d, 0).map_or(0, u64::from),
                }
            }
        };
        let at = p;
        cx.mark(move || at);
        let span = t.file.sub(p.offset, size);
        let mut node = Node::new(format!("Sample {}", p.sample.saturating_add(1)))
            .span(span)
            .summary(format!("{size} bytes, chunk {}", p.chunk));
        if span.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, size),
                span.len,
            ));
        }
        if let Some(d) = usize::try_from(p.desc.saturating_sub(1))
            .ok()
            .and_then(|i| t.configs.get(i))
        {
            node = d.apply(node, span);
        }
        cx.progress(p.sample, samples);
        cx.push(node).await;
        p.offset = p.offset.saturating_add(size);
        p.left = p.left.saturating_sub(1);
        p.sample = p.sample.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Track fragment runs

/// Where a track run's samples are and how to read their sizes.
#[derive(Clone, Debug)]
struct Run {
    input: Input,
    /// The run's sample entries (after the header fields).
    entries: Span,
    count: u64,
    flags: u32,
    /// File offset of the first sample.
    start: u64,
    /// Sample size when the entries do not hold one.
    default_size: Option<u64>,
    /// 1-based sample description index.
    desc: u64,
    /// The track's `stbl`, for its sample descriptions.
    stbl: Option<Span>,
}

/// Defaults of a track from `moov`: its `stbl` and the `trex` sample
/// description index and size.
struct TrackDefaults {
    stbl: Option<Span>,
    desc: Option<u64>,
    size: Option<u64>,
}

/// Looks up track `id` in the file's `moov` (at most 64 tracks).
async fn track_defaults(cx: &Cx, file: Span, id: u32) -> Result<TrackDefaults> {
    let mut out = TrackDefaults {
        stbl: None,
        desc: None,
        size: None,
    };
    let Some((h, moov)) = find_child(cx, file, b"moov").await? else {
        return Ok(out);
    };
    let moov = moov.tail(h.header_len);
    let mut pos = 0u64;
    let mut seen = 0u32;
    while let Some(b) = read_header(cx, moov, pos).await? {
        let body = moov.sub(pos, b.size).tail(b.header_len);
        if &b.kind == b"trak" && out.stbl.is_none() {
            if let Some((th, tkhd)) = find_child(cx, body, b"tkhd").await? {
                let d = cx.read_avail(tkhd.tail(th.header_len).sub(0, 24)).await?;
                let at = if d.first() == Some(&1) { 20 } else { 12 };
                if u32_be(&d, at) == Some(id) {
                    let mut region = Some(body);
                    for kind in [b"mdia", b"minf", b"stbl"] {
                        region = match region {
                            Some(r) => find_child(cx, r, kind)
                                .await?
                                .map(|(h, s)| s.tail(h.header_len)),
                            None => None,
                        };
                    }
                    out.stbl = region;
                }
            }
        } else if &b.kind == b"mvex" {
            let mut at = 0u64;
            while let Some(x) = read_header(cx, body, at).await? {
                if &x.kind == b"trex" {
                    let d = cx
                        .read_avail(body.sub(at, x.size).tail(x.header_len).sub(0, 24))
                        .await?;
                    if u32_be(&d, 4) == Some(id) {
                        out.desc = u32_be(&d, 8).map(u64::from);
                        out.size = u32_be(&d, 16).map(u64::from);
                    }
                }
                at = at.saturating_add(x.size);
                if x.size == 0 || x.to_end {
                    break;
                }
                cx.checkpoint().await;
            }
        }
        pos = pos.saturating_add(b.size);
        seen = seen.saturating_add(1);
        if b.to_end || seen > 64 {
            break;
        }
    }
    Ok(out)
}

/// A lazy "Sample data" node for a `trun` whose entries are `entries`,
/// when its data can be located: `start` is the file offset of its first
/// sample, `traf` the track fragment's boxes (for `tfhd`).
pub async fn run_node(
    cx: &Cx,
    input: Input,
    traf: Span,
    entries: Span,
    count: u64,
    flags: u32,
    start: u64,
) -> Result<Option<Node>> {
    let Some((h, tfhd)) = find_child(cx, traf, b"tfhd").await? else {
        return Ok(None);
    };
    let d = cx.read_avail(tfhd.tail(h.header_len).sub(0, 40)).await?;
    let tf = u32_be(&d, 0).unwrap_or(0) & 0x00ff_ffff;
    let Some(id) = u32_be(&d, 4) else {
        return Ok(None);
    };
    // Optional fields in order: base offset (8), description index,
    // duration, size, flags (4 each).
    let mut at = 8usize;
    if tf & 0x1 != 0 {
        at = at.saturating_add(8);
    }
    let mut desc = None;
    if tf & 0x2 != 0 {
        desc = u32_be(&d, at).map(u64::from);
        at = at.saturating_add(4);
    }
    if tf & 0x8 != 0 {
        at = at.saturating_add(4);
    }
    let mut size = None;
    if tf & 0x10 != 0 {
        size = u32_be(&d, at).map(u64::from);
    }
    let defaults = track_defaults(cx, input.span, id).await?;
    let run = Run {
        input,
        entries,
        count,
        flags,
        start,
        default_size: size.or(defaults.size),
        desc: desc.or(defaults.desc).unwrap_or(1),
        stbl: defaults.stbl,
    };
    if flags & 0x200 == 0 && run.default_size.unwrap_or(0) == 0 {
        return Ok(None);
    }
    Ok(Some(
        Node::new("Sample data")
            .span(input.span.sub(start, 0))
            .summary(format!("{}, track {id}", plural(count, "sample")))
            .desc("Each sample's bytes, located from the base data offset, the data offset and the sample sizes")
            .lazy(expand_run, run),
    ))
}

async fn expand_run(cx: Cx, run: Run) -> Result<()> {
    let configs = match run.stbl {
        Some(stbl) => configs(&cx, stbl).await?,
        None => Vec::new(),
    };
    let decode = usize::try_from(run.desc.saturating_sub(1))
        .ok()
        .and_then(|i| configs.get(i))
        .cloned()
        .unwrap_or(Decode::None);
    let stride = u64::from((run.flags & 0xf00).count_ones()).saturating_mul(4);
    // The size's place in each entry: after the duration, if present.
    let size_at = if run.flags & 0x100 != 0 { 4 } else { 0 };
    let count = if stride > 0 {
        run.count
            .min(run.entries.len.checked_div(stride).unwrap_or(0))
    } else {
        run.count
    };
    let file = run.input.span;
    let mut entries = Window::new(run.entries);
    let mut offset = run.start;
    let mut index = 0u64;
    while index < count {
        if offset >= file.len {
            cx.diag(Diagnostic::malformed(format!(
                "samples {}-{count} lie past the end of the file",
                index.saturating_add(1)
            )));
            break;
        }
        let size = if run.flags & 0x200 != 0 {
            let e = entries
                .get(&cx, index.saturating_mul(stride).saturating_add(size_at), 4)
                .await?;
            u32_be(e, 0).map_or(0, u64::from)
        } else {
            run.default_size.unwrap_or(0)
        };
        let span = file.sub(offset, size);
        let mut node = Node::new(format!("Sample {}", index.saturating_add(1)))
            .span(span)
            .summary(format!("{size} bytes"));
        if span.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, size),
                span.len,
            ));
        }
        node = decode.apply(node, span);
        cx.push(node).await;
        offset = offset.saturating_add(size);
        index = index.saturating_add(1);
    }
    Ok(())
}
