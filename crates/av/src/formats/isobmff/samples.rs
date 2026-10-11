//! The samples of a track, located in the file from its sample table:
//! `stsc` maps samples to chunks, `stco`/`co64` give each chunk's file
//! offset, `stsz`/`stz2` each sample's size (ISO 14496-12 8.7). Listed
//! lazily in pages with resume marks; the tables are read a window at a
//! time, never whole. Video samples of AVC, HEVC, AV1 and VP9 tracks split
//! into NAL units, OBUs or the VP9 frame header ([`coded`]).

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::formats::util::fmt::plural;
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
    /// Frame splitting per sample description (index - 1).
    configs: Arc<Vec<Arc<coded::Config>>>,
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

/// Frame splitting for each sample description in `stsd` (at most
/// [`MAX_DESCRIPTIONS`]).
async fn configs(cx: &Cx, stbl: Span) -> Result<Vec<Arc<coded::Config>>> {
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
        let kind = coded::Kind::from_fourcc(&e.kind);
        let mut config = coded::Config::bare(kind);
        if kind != coded::Kind::Other {
            let body = entries.sub(pos, e.size).tail(e.header_len);
            let d = small(cx, body).await?;
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
        out.push(Arc::new(config));
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
        let config = usize::try_from(p.desc.saturating_sub(1))
            .ok()
            .and_then(|i| t.configs.get(i));
        if let Some(c) = config
            && c.splits()
            && !span.is_empty()
        {
            node = node.lazy(
                coded::expand,
                coded::Frame {
                    span,
                    config: c.clone(),
                },
            );
        }
        cx.progress(p.sample, samples);
        cx.push(node).await;
        p.offset = p.offset.saturating_add(size);
        p.left = p.left.saturating_sub(1);
        p.sample = p.sample.saturating_add(1);
    }
    Ok(())
}
