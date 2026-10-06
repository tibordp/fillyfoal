//! Sample tables and other fixed-stride lists: `stts`, `ctts`, `stsc`,
//! `stsz`, `stco`, `co64`, `stss`, `elst`, `sidx`, `trun`, `sbgp`.
//! Entries are listed in pages; a table is never read whole.

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Fields, struct_node};
use crate::formats::util::vidutil::{Entry, table};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{Radix, Value};

use super::boxes::sample_flags;
use super::{BE, BoxState, full_box, small};

record! {
    pub struct TimeToSample {
        count: u32 "Sample count",
        delta: u32 "Sample delta",
    }
}

impl Entry for TimeToSample {
    fn summary(&self) -> Option<String> {
        Some(format!("{} × {}", self.count, self.delta))
    }
}

record! {
    pub struct CompositionOffset {
        count: u32 "Sample count",
        offset: i32 "Sample offset",
    }
}

impl Entry for CompositionOffset {
    fn summary(&self) -> Option<String> {
        Some(format!("{} × {:+}", self.count, self.offset))
    }
}

record! {
    pub struct SampleToChunk {
        first: u32 "First chunk",
        per_chunk: u32 "Samples per chunk",
        description: u32 "Sample description index",
    }
}

impl Entry for SampleToChunk {
    fn summary(&self) -> Option<String> {
        Some(format!(
            "from chunk {}: {} samples per chunk, description {}",
            self.first, self.per_chunk, self.description
        ))
    }
}

record! {
    pub struct SampleSize {
        size: u32 "Size",
    }
}

impl Entry for SampleSize {
    fn label(index: u64) -> String {
        format!("Sample {}", index.saturating_add(1))
    }
    fn leaf(&self) -> Option<Value> {
        Some(Value::UInt {
            value: self.size.into(),
            bits: 32,
            radix: Radix::Dec,
        })
    }
}

record! {
    pub struct ChunkOffset {
        offset: u32 "Offset",
    }
}

impl Entry for ChunkOffset {
    fn label(index: u64) -> String {
        format!("Chunk {}", index.saturating_add(1))
    }
    fn leaf(&self) -> Option<Value> {
        Some(Value::UInt {
            value: self.offset.into(),
            bits: 32,
            radix: Radix::Hex,
        })
    }
}

record! {
    pub struct ChunkOffset64 {
        offset: u64 "Offset",
    }
}

impl Entry for ChunkOffset64 {
    fn label(index: u64) -> String {
        format!("Chunk {}", index.saturating_add(1))
    }
    fn leaf(&self) -> Option<Value> {
        Some(Value::UInt {
            value: self.offset,
            bits: 64,
            radix: Radix::Hex,
        })
    }
}

record! {
    pub struct SampleNumber {
        sample: u32 "Sample number",
    }
}

impl Entry for SampleNumber {
    fn leaf(&self) -> Option<Value> {
        Some(Value::UInt {
            value: self.sample.into(),
            bits: 32,
            radix: Radix::Dec,
        })
    }
}

record! {
    pub struct EditV0 {
        duration: u32 "Segment duration",
        media_time: i32 "Media time",
        rate: i16 "Media rate integer",
        fraction: i16 "Media rate fraction",
    }
}

impl Entry for EditV0 {
    fn summary(&self) -> Option<String> {
        Some(edit_summary(
            self.duration.into(),
            self.media_time.into(),
            self.rate,
        ))
    }
}

record! {
    pub struct EditV1 {
        duration: u64 "Segment duration",
        media_time: i64 "Media time",
        rate: i16 "Media rate integer",
        fraction: i16 "Media rate fraction",
    }
}

impl Entry for EditV1 {
    fn summary(&self) -> Option<String> {
        Some(edit_summary(self.duration, self.media_time, self.rate))
    }
}

fn edit_summary(duration: u64, media_time: i64, rate: i16) -> String {
    if media_time == -1 {
        format!("empty edit, duration {duration}")
    } else {
        format!("duration {duration} from media time {media_time}, rate {rate}")
    }
}

record! {
    pub struct SegmentReference {
        reference: u32 "Reference type / size" .hex(),
        duration: u32 "Subsegment duration",
        sap: u32 "SAP flags" .hex(),
    }
}

impl Entry for SegmentReference {
    fn summary(&self) -> Option<String> {
        let kind = if self.reference >> 31 == 1 {
            "index"
        } else {
            "media"
        };
        let sap = if self.sap >> 31 == 1 {
            ", starts with SAP"
        } else {
            ""
        };
        Some(format!(
            "{kind}, {} bytes, duration {}{sap}",
            self.reference & 0x7fff_ffff,
            self.duration
        ))
    }
}

record! {
    pub struct SampleToGroup {
        count: u32 "Sample count",
        index: u32 "Group description index",
    }
}

impl Entry for SampleToGroup {
    fn summary(&self) -> Option<String> {
        Some(format!("{} samples → group {}", self.count, self.index))
    }
}

/// Decodes table boxes. Returns `false` for other types.
pub async fn decode(cx: &Cx, st: &BoxState) -> Result<bool> {
    let body = st.body();
    let kind = st.header.kind;
    let simple = |count_at: u64| body.tail(count_at.saturating_add(4));
    match &kind {
        b"stts" | b"ctts" | b"stsc" | b"stco" | b"co64" | b"stss" | b"stps" | b"elst" => {
            let (version, count) = header(cx, body, |f| {
                let (v, _) = full_box(f)?;
                let n = f.u32("Entry count").emit()?;
                Ok((v, n))
            })
            .await?;
            let entries = simple(4);
            let n = u64::from(count);
            cx.emit(match &kind {
                b"stts" => table::<TimeToSample>("Entries", entries, n, BE),
                b"ctts" => table::<CompositionOffset>("Entries", entries, n, BE),
                b"stsc" => table::<SampleToChunk>("Entries", entries, n, BE),
                b"stco" => table::<ChunkOffset>("Chunk offsets", entries, n, BE),
                b"co64" => table::<ChunkOffset64>("Chunk offsets", entries, n, BE),
                b"elst" if version == 1 => table::<EditV1>("Edits", entries, n, BE),
                b"elst" => table::<EditV0>("Edits", entries, n, BE),
                _ => table::<SampleNumber>("Sync samples", entries, n, BE),
            });
        }
        b"stsz" => {
            let (size, count) = header(cx, body, |f| {
                full_box(f)?;
                let size = f
                    .u32("Sample size")
                    .desc("0 = sizes listed per sample")
                    .emit()?;
                let n = f.u32("Sample count").emit()?;
                Ok((size, n))
            })
            .await?;
            if size == 0 {
                cx.emit(table::<SampleSize>(
                    "Sample sizes",
                    body.tail(12),
                    count.into(),
                    BE,
                ));
            }
        }
        b"stz2" => {
            header(cx, body, |f| {
                full_box(f)?;
                f.bytes("Reserved", 3).emit()?;
                f.u8("Field size").emit()?;
                f.u32("Sample count").emit()?;
                Ok(())
            })
            .await?;
            cx.emit(Node::new("Packed sample sizes").span(body.tail(12)));
        }
        b"sbgp" => {
            let count = header(cx, body, |f| {
                let (v, _) = full_box(f)?;
                f.ascii("Grouping type", 4).emit()?;
                if v == 1 {
                    f.u32("Grouping type parameter").emit()?;
                }
                f.u32("Entry count").emit()
            })
            .await?;
            let (v, _) = super::version_flags(cx, body).await?;
            let at = if v == 1 { 16 } else { 12 };
            cx.emit(table::<SampleToGroup>(
                "Entries",
                body.tail(at),
                count.into(),
                BE,
            ));
        }
        b"sidx" => {
            let (wide, count) = header(cx, body, |f| {
                let (v, _) = full_box(f)?;
                f.u32("Reference ID").emit()?;
                f.u32("Timescale").emit()?;
                f.uword("Earliest presentation time", v != 0).emit()?;
                f.uword("First offset", v != 0).emit()?;
                f.u16("Reserved").emit()?;
                let n = f.u16("Reference count").emit()?;
                Ok((v != 0, n))
            })
            .await?;
            let at = if wide { 32 } else { 24 };
            cx.emit(table::<SegmentReference>(
                "References",
                body.tail(at),
                count.into(),
                BE,
            ));
        }
        b"trun" => {
            let (flags, count, at) = header(cx, body, |f| {
                let (_, flags) = full_box(f)?;
                let n = f.u32("Sample count").emit()?;
                if flags & 0x1 != 0 {
                    f.i32("Data offset").emit()?;
                }
                if flags & 0x4 != 0 {
                    f.u32("First sample flags")
                        .hex()
                        .with(|&v, n| n.summary(sample_flags(v)))
                        .emit()?;
                }
                Ok((flags, n, f.pos()))
            })
            .await?;
            let stride = trun_stride(flags);
            let entries = body.tail(at);
            let mut node = Node::new("Samples")
                .span(entries)
                .summary(crate::formats::util::vidutil::plural(count, "sample"));
            if stride > 0 {
                node = node.lazy(trun_samples, (entries, u64::from(count), flags));
            }
            cx.emit(node);
        }
        b"sdtp" => {
            header(cx, body, |f| full_box(f).map(|_| ())).await?;
            cx.emit(
                Node::new("Dependency flags")
                    .span(body.tail(4))
                    .summary(format!("{} samples", body.len.saturating_sub(4))),
            );
        }
        b"cslg" => {
            header(cx, body, |f| {
                let (v, _) = full_box(f)?;
                for name in [
                    "Composition to DTS shift",
                    "Least decode to display delta",
                    "Greatest decode to display delta",
                    "Composition start time",
                    "Composition end time",
                ] {
                    if v == 0 {
                        f.i32(name).emit()?;
                    } else {
                        f.int::<i64>(name).emit()?;
                    }
                }
                Ok(())
            })
            .await?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Emits the fixed fields at the start of a table box.
async fn header<T>(
    cx: &Cx,
    body: Span,
    layout: impl FnOnce(&mut Fields<'_>) -> Result<T>,
) -> Result<T> {
    let block = cx.block(body.sub(0, 64)).await?;
    layout(&mut Fields::emitting(cx, &block, BE))
}

/// Entry counts for the box list.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let kind = &st.header.kind;
    let at = match kind {
        b"stts" | b"ctts" | b"stsc" | b"stco" | b"co64" | b"stss" | b"stps" | b"elst" | b"trun" => {
            4
        }
        b"stsz" | b"stz2" => 8,
        b"sidx" | b"sbgp" => 0,
        _ => return None,
    };
    let d = small(cx, st.body().sub(0, 40)).await.ok()?;
    let wide = d.first().copied().unwrap_or(0) != 0;
    match kind {
        b"stsz" => {
            let size = u32_be(&d, 4)?;
            let n = u32_be(&d, 8)?;
            Some(if size == 0 {
                crate::formats::util::vidutil::plural(n, "sample")
            } else {
                format!(
                    "{} of {size} bytes",
                    crate::formats::util::vidutil::plural(n, "sample")
                )
            })
        }
        b"sidx" => Some(format!(
            "{} references",
            u16_be(&d, if wide { 30 } else { 22 })?
        )),
        b"sbgp" => Some(format!(
            "{} entries ({})",
            u32_be(&d, if wide { 12 } else { 8 })?,
            crate::formats::util::vidutil::fourcc(d.get(4..8)?)
        )),
        b"trun" => Some(crate::formats::util::vidutil::plural(
            u32_be(&d, at)?,
            "sample",
        )),
        _ => Some(entries(u32_be(&d, at)?.into())),
    }
}

/// "1 entry", "2 entries".
pub fn entries(n: u64) -> String {
    if n == 1 {
        "1 entry".to_owned()
    } else {
        format!("{n} entries")
    }
}

fn trun_stride(flags: u32) -> u64 {
    u64::from((flags & 0xf00).count_ones()).saturating_mul(4)
}

const PAGE: u64 = 256;

async fn trun_samples(cx: Cx, (span, count, flags): (Span, u64, u32)) -> Result<()> {
    let stride = trun_stride(flags);
    let fits = span.len.checked_div(stride).unwrap_or(0);
    let count = count.min(fits);
    cx.set_count(Count::Exact(count));
    let mut index = 0u64;
    while index < count {
        let n = count.saturating_sub(index).min(PAGE);
        let page = span.sub(index.saturating_mul(stride), n.saturating_mul(stride));
        let block = cx.block(page).await?;
        for j in 0..n {
            let at = j.saturating_mul(stride);
            let entry = page.sub(at, stride);
            let mut f = Fields::new(&block, BE);
            f.seek(at);
            let sample = trun_entry(&mut f, &flags)?;
            cx.push(
                struct_node(
                    format!("Sample {}", index.saturating_add(j).saturating_add(1)),
                    entry,
                    BE,
                    flags,
                    trun_entry,
                )
                .summary(sample),
            )
            .await;
        }
        index = index.saturating_add(n);
    }
    Ok(())
}

/// One `trun` sample; returns its summary.
fn trun_entry(f: &mut Fields<'_>, flags: &u32) -> Result<String> {
    let mut parts = Vec::new();
    if flags & 0x100 != 0 {
        let d = f.u32("Duration").emit()?;
        parts.push(format!("duration {d}"));
    }
    if flags & 0x200 != 0 {
        let s = f.u32("Size").emit()?;
        parts.push(format!("{s} bytes"));
    }
    if flags & 0x400 != 0 {
        let v = f
            .u32("Flags")
            .hex()
            .with(|&v, n| n.summary(sample_flags(v)))
            .emit()?;
        parts.push(sample_flags(v));
    }
    if flags & 0x800 != 0 {
        let c = f.i32("Composition time offset").emit()?;
        parts.push(format!("cto {c:+}"));
    }
    Ok(parts.join(", "))
}
