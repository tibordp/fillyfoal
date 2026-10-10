//! Sample tables and other lists: `stts`, `ctts`, `stsc`, `stsz`, `stz2`,
//! `stco`, `co64`, `stss`, `sdtp`, `sbgp`, `sgpd`, `elst`, `sidx`, `trun`,
//! `tfra`, and the common-encryption auxiliary data `senc`, `saiz`, `saio`.
//! Entries are listed in pages; a table is never read whole.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::util::vidutil::{
    Entry, duration, enumerated, fourcc, num, read_small, table, text, uuid,
};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

use super::boxes::sample_flags;
use super::{BE, BoxState, full_box, small};
use crate::formats::util::fmt::plural;

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
            "from chunk {}: {} per chunk, description {}",
            self.first,
            plural(self.per_chunk, "sample"),
            self.description
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
    pub struct SampleSize8 {
        size: u8 "Size",
    }
}

impl Entry for SampleSize8 {
    fn label(index: u64) -> String {
        format!("Sample {}", index.saturating_add(1))
    }
    fn leaf(&self) -> Option<Value> {
        Some(Value::UInt {
            value: self.size.into(),
            bits: 8,
            radix: Radix::Dec,
        })
    }
}

record! {
    pub struct SampleSize16 {
        size: u16 "Size",
    }
}

impl Entry for SampleSize16 {
    fn label(index: u64) -> String {
        format!("Sample {}", index.saturating_add(1))
    }
    fn leaf(&self) -> Option<Value> {
        Some(Value::UInt {
            value: self.size.into(),
            bits: 16,
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
    pub struct AuxOffset {
        offset: u32 "Offset",
    }
}

impl Entry for AuxOffset {
    fn label(index: u64) -> String {
        format!("Offset {}", index.saturating_add(1))
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
    pub struct AuxOffset64 {
        offset: u64 "Offset",
    }
}

impl Entry for AuxOffset64 {
    fn label(index: u64) -> String {
        format!("Offset {}", index.saturating_add(1))
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

const LEADING: EnumTable = &[
    (0, "unknown"),
    (1, "leading, depends on a preceding I-picture"),
    (2, "not leading"),
    (3, "leading, decodable"),
];
const DEPENDS_ON: EnumTable = &[
    (0, "unknown"),
    (1, "depends on others"),
    (2, "independent (I-picture)"),
    (3, "reserved"),
];
const DEPENDED_ON: EnumTable = &[
    (0, "unknown"),
    (1, "other samples depend on it"),
    (2, "disposable"),
    (3, "reserved"),
];
const REDUNDANCY: EnumTable = &[
    (0, "unknown"),
    (1, "redundant coding"),
    (2, "no redundant coding"),
    (3, "reserved"),
];

record! {
    pub struct SampleDependency {
        flags: u8 "Flags" .hex(),
    }
}

impl Entry for SampleDependency {
    fn label(index: u64) -> String {
        format!("Sample {}", index.saturating_add(1))
    }
    fn summary(&self) -> Option<String> {
        let v = u64::from(self.flags);
        let mut parts = Vec::new();
        if let Some(s) =
            crate::value::lookup(DEPENDS_ON, (v >> 4) & 3).filter(|_| (v >> 4) & 3 != 0)
        {
            parts.push(s);
        }
        if let Some(s) =
            crate::value::lookup(DEPENDED_ON, (v >> 2) & 3).filter(|_| (v >> 2) & 3 != 0)
        {
            parts.push(s);
        }
        if let Some(s) = crate::value::lookup(LEADING, v >> 6).filter(|_| v >> 6 != 0) {
            parts.push(s);
        }
        if v & 3 == 1 {
            parts.push("redundant coding");
        }
        Some(if parts.is_empty() {
            "unknown".to_owned()
        } else {
            parts.join(", ")
        })
    }
}

fn dependency_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let byte = f.peek_span(1);
    let v = u64::from(f.u8("Flags").get()?);
    f.node(enumerated("Is leading", byte, v >> 6, 2, LEADING));
    f.node(enumerated("Depends on", byte, (v >> 4) & 3, 2, DEPENDS_ON));
    f.node(enumerated(
        "Is depended on",
        byte,
        (v >> 2) & 3,
        2,
        DEPENDED_ON,
    ));
    f.node(enumerated("Has redundancy", byte, v & 3, 2, REDUNDANCY));
    Ok(())
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
            format!(", starts with SAP type {}", (self.sap >> 28) & 7)
        } else {
            String::new()
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
        Some(if self.index == 0 {
            format!("{} → no group", plural(self.count, "sample"))
        } else {
            format!("{} → group {}", plural(self.count, "sample"), self.index)
        })
    }
}

/// Decodes table boxes. Returns `false` for other types.
pub async fn decode(cx: &Cx, st: &BoxState) -> Result<bool> {
    let body = st.body();
    let kind = st.header.kind;
    let ctx = st.ctx;
    let simple = |count_at: u64| body.tail(count_at.saturating_add(4));
    match &kind {
        b"stts" | b"ctts" | b"stsc" | b"stco" | b"co64" | b"stss" | b"stps" => {
            let count = header(cx, body, |f| {
                full_box(f)?;
                f.u32("Entry count").emit()
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
                _ => table::<SampleNumber>("Sync samples", entries, n, BE),
            });
        }
        b"elst" => {
            let (version, count) = header(cx, body, |f| {
                let (v, _) = full_box(f)?;
                let n = f.u32("Entry count").emit()?;
                Ok((v, n))
            })
            .await?;
            let edits = Edits {
                span: simple(4),
                count: count.into(),
                wide: version == 1,
                movie: ctx.movie_timescale,
                media: ctx.media_timescale,
            };
            cx.emit(
                Node::new("Edits")
                    .span(edits.span)
                    .summary(plural(count, "edit"))
                    .lazy(expand_edits, edits),
            );
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
            let (bits, count) = header(cx, body, |f| {
                full_box(f)?;
                f.bytes("Reserved", 3).emit()?;
                let bits = f
                    .u8("Field size")
                    .desc("Bits per entry: 4, 8 or 16")
                    .emit()?;
                let n = f.u32("Sample count").emit()?;
                Ok((bits, n))
            })
            .await?;
            let list = body.tail(12);
            let n = u64::from(count);
            cx.emit(match bits {
                8 => table::<SampleSize8>("Sample sizes", list, n, BE),
                16 => table::<SampleSize16>("Sample sizes", list, n, BE),
                4 => Node::new("Sample sizes")
                    .span(list)
                    .summary(entries(n))
                    .lazy(expand_nibbles, (list, n)),
                _ => Node::new("Sample sizes")
                    .span(list)
                    .diag(Diagnostic::malformed(format!("invalid field size {bits}"))),
            });
        }
        b"sbgp" => {
            let (v, count) = header(cx, body, |f| {
                let (v, _) = full_box(f)?;
                f.ascii("Grouping type", 4)
                    .with(|t, n| match grouping_name(t.as_bytes()) {
                        Some(s) => n.summary(s),
                        None => n,
                    })
                    .emit()?;
                if v == 1 {
                    f.u32("Grouping type parameter").emit()?;
                }
                Ok((v, f.u32("Entry count").emit()?))
            })
            .await?;
            let at = if v == 1 { 16 } else { 12 };
            cx.emit(table::<SampleToGroup>(
                "Entries",
                body.tail(at),
                count.into(),
                BE,
            ));
        }
        b"sgpd" => sgpd(cx, body).await?,
        b"sidx" => {
            let (wide, count) = header(cx, body, |f| {
                let (v, _) = full_box(f)?;
                f.u32("Reference ID").emit()?;
                let ts = f.u32("Timescale").emit()?;
                f.uword("Earliest presentation time", v != 0)
                    .with(|&t, n| {
                        if ts == 0 {
                            n
                        } else {
                            n.summary(duration(t, ts.into()))
                        }
                    })
                    .emit()?;
                f.uword("First offset", v != 0)
                    .desc("From the end of this box to the first referenced byte")
                    .emit()?;
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
                let (_, flags) = super::full_box_flags(f, TRUN_FLAGS)?;
                let n = f.u32("Sample count").emit()?;
                if flags & 0x1 != 0 {
                    f.i32("Data offset")
                        .desc("Relative to the base data offset (tfhd), usually the moof")
                        .emit()?;
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
                .summary(plural(count, "sample"));
            if stride > 0 {
                node = node.lazy(trun_samples, (entries, u64::from(count), flags));
            }
            cx.emit(node);
        }
        b"sdtp" => {
            header(cx, body, |f| full_box(f).map(|_| ())).await?;
            let entries = body.tail(4);
            cx.emit(
                Node::new("Samples")
                    .span(entries)
                    .summary(plural(entries.len, "sample"))
                    .lazy(expand_dependencies, entries),
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
        b"saiz" => {
            let (default, count) = header(cx, body, |f| {
                let (_, flags) = full_box(f)?;
                if flags & 1 != 0 {
                    f.ascii("Aux info type", 4).emit()?;
                    f.u32("Aux info type parameter").emit()?;
                }
                let d = f
                    .u8("Default sample info size")
                    .desc("0 = sizes listed per sample")
                    .emit()?;
                let n = f.u32("Sample count").emit()?;
                Ok((d, (n, f.pos())))
            })
            .await?;
            let (n, at) = count;
            if default == 0 {
                cx.emit(table::<SampleSize8>(
                    "Sample info sizes",
                    body.tail(at),
                    n.into(),
                    BE,
                ));
            }
        }
        b"saio" => {
            let (wide, (n, at)) = header(cx, body, |f| {
                let (v, flags) = full_box(f)?;
                if flags & 1 != 0 {
                    f.ascii("Aux info type", 4).emit()?;
                    f.u32("Aux info type parameter").emit()?;
                }
                let n = f.u32("Entry count").emit()?;
                Ok((v == 1, (n, f.pos())))
            })
            .await?;
            let offsets = body.tail(at);
            cx.emit(if wide {
                table::<AuxOffset64>("Offsets", offsets, n.into(), BE)
            } else {
                table::<AuxOffset>("Offsets", offsets, n.into(), BE)
            }
            .desc("Where the auxiliary information (IVs) starts: from the moof in fragments, else from the file start"));
        }
        b"senc" => senc(cx, body).await?,
        b"tfra" => {
            let t = header(cx, body, |f| {
                let (v, _) = full_box(f)?;
                f.u32("Track ID").emit()?;
                let sizes = f
                    .u32("Field sizes")
                    .hex()
                    .with(|&v, n| {
                        n.summary(format!(
                            "traf {} bytes, trun {} bytes, sample {} bytes",
                            ((v >> 4) & 3).saturating_add(1),
                            ((v >> 2) & 3).saturating_add(1),
                            (v & 3).saturating_add(1)
                        ))
                    })
                    .emit()?;
                let n = f.u32("Entry count").emit()?;
                let pos = f.pos();
                Ok(Tfra {
                    span: body.tail(pos),
                    count: n.into(),
                    wide: v == 1,
                    traf: u64::from((sizes >> 4) & 3).saturating_add(1),
                    trun: u64::from((sizes >> 2) & 3).saturating_add(1),
                    sample: u64::from(sizes & 3).saturating_add(1),
                })
            })
            .await?;
            cx.emit(
                Node::new("Entries")
                    .span(t.span)
                    .summary(entries(t.count))
                    .lazy(expand_tfra, t),
            );
        }
        _ => return Ok(false),
    }
    Ok(true)
}

const TRUN_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x1, "DATA_OFFSET"),
    crate::value::flag(0x4, "FIRST_SAMPLE_FLAGS"),
    crate::value::flag(0x100, "SAMPLE_DURATION"),
    crate::value::flag(0x200, "SAMPLE_SIZE"),
    crate::value::flag(0x400, "SAMPLE_FLAGS"),
    crate::value::flag(0x800, "SAMPLE_COMPOSITION_TIME_OFFSET"),
];

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
        b"stts" | b"ctts" | b"stsc" | b"stco" | b"co64" | b"stss" | b"stps" | b"elst" | b"trun"
        | b"senc" => 4,
        b"stsz" | b"stz2" => 8,
        b"sidx" | b"sbgp" | b"sgpd" | b"saiz" | b"saio" | b"tfra" | b"sdtp" => 0,
        _ => return None,
    };
    let d = small(cx, st.body().sub(0, 64)).await.ok()?;
    let version = d.first().copied().unwrap_or(0);
    let wide = version != 0;
    match kind {
        b"stts" => {
            let n = u32_be(&d, at)?;
            let mut s = entries(n.into());
            if n == 1
                && let (Some(count), Some(delta)) = (u32_be(&d, 8), u32_be(&d, 12))
            {
                s = format!("{} × {delta}", plural(count, "sample"));
                let ts = st.ctx.media_timescale;
                if &st.ctx.handler == b"vide" && ts > 0 && delta > 0 {
                    s = format!("{s} ({} fps)", fps(f64::from(ts) / f64::from(delta)));
                }
            }
            Some(s)
        }
        b"stss" => Some(plural(u32_be(&d, at)?, "sync sample")),
        b"stco" | b"co64" => Some(plural(u32_be(&d, at)?, "chunk")),
        b"elst" => {
            let n = u32_be(&d, at)?;
            if n != 1 {
                return Some(plural(n, "edit"));
            }
            let edit = if wide {
                Edit {
                    duration: u64_be(&d, 8)?,
                    media_time: i64::from_be_bytes(crate::bytes::array(&d, 16)?),
                    rate: u32_be(&d, 24)? as i32,
                }
            } else {
                Edit {
                    duration: u32_be(&d, 8)?.into(),
                    media_time: (u32_be(&d, 12)? as i32).into(),
                    rate: u32_be(&d, 16)? as i32,
                }
            };
            Some(edit.summary(st.ctx.movie_timescale, st.ctx.media_timescale))
        }
        b"stsz" => {
            let size = u32_be(&d, 4)?;
            let n = u32_be(&d, 8)?;
            Some(if size == 0 {
                plural(n, "sample")
            } else {
                format!("{} of {size} bytes", plural(n, "sample"))
            })
        }
        b"stz2" => Some(format!(
            "{}, {}-bit sizes",
            plural(u32_be(&d, 8)?, "sample"),
            d.get(7)?
        )),
        b"sidx" => {
            let ts = u32_be(&d, 8)?;
            Some(format!(
                "{}, timescale {ts}",
                plural(u16_be(&d, if wide { 30 } else { 22 })?, "reference")
            ))
        }
        b"sbgp" => Some(format!(
            "{}: {}",
            fourcc(d.get(4..8)?),
            entries(u32_be(&d, if version == 1 { 12 } else { 8 })?.into()),
        )),
        b"sgpd" => {
            let t = d.get(4..8)?;
            let n = u32_be(&d, if version >= 1 { 12 } else { 8 })?;
            Some(match grouping_name(t) {
                Some(name) => format!("{} ({name}): {}", fourcc(t), plural(n, "description")),
                None => format!("{}: {}", fourcc(t), plural(n, "description")),
            })
        }
        b"saiz" => {
            let flags = u32_be(&d, 0)? & 0x00ff_ffff;
            let at = if flags & 1 != 0 { 12 } else { 4 };
            let default = *d.get(at)?;
            let n = u32_be(&d, at.saturating_add(1))?;
            Some(if default > 0 {
                format!("{} of {default} bytes", plural(n, "sample"))
            } else {
                plural(n, "sample")
            })
        }
        b"saio" => {
            let flags = u32_be(&d, 0)? & 0x00ff_ffff;
            let at = if flags & 1 != 0 { 12 } else { 4 };
            Some(plural(u32_be(&d, at)?, "offset"))
        }
        b"senc" => {
            let flags = u32_be(&d, 0)? & 0x00ff_ffff;
            let mut s = plural(u32_be(&d, at)?, "sample");
            if flags & 2 != 0 {
                s.push_str(", with subsamples");
            }
            Some(s)
        }
        b"tfra" => Some(format!(
            "track {}, {}",
            u32_be(&d, 4)?,
            entries(u32_be(&d, 12)?.into())
        )),
        b"sdtp" => Some(plural(st.body().len.saturating_sub(4), "sample")),
        b"trun" => Some(plural(u32_be(&d, at)?, "sample")),
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

/// A frame rate, with the customary three decimals for NTSC rates.
pub fn fps(rate: f64) -> String {
    let rounded = (rate * 100.0).round() / 100.0;
    if rounded.fract() == 0.0 {
        format!("{rounded:.0}")
    } else {
        let s = format!("{rate:.3}");
        let s = s.trim_end_matches('0');
        s.trim_end_matches('.').to_owned()
    }
}

// ---------------------------------------------------------------------------
// Edit lists

#[derive(Clone, Copy, Debug)]
struct Edits {
    span: Span,
    count: u64,
    wide: bool,
    movie: u32,
    media: u32,
}

#[derive(Clone, Copy, Debug)]
struct Edit {
    duration: u64,
    media_time: i64,
    /// 16.16 fixed point.
    rate: i32,
}

impl Edit {
    fn summary(&self, movie: u32, media: u32) -> String {
        let length = if movie > 0 {
            duration(self.duration, movie.into())
        } else {
            format!("{} units", self.duration)
        };
        if self.media_time == -1 {
            return format!("empty, {length}");
        }
        let from = match u64::try_from(self.media_time) {
            Ok(t) if media > 0 => duration(t, media.into()),
            _ => format!("{}", self.media_time),
        };
        let mut s = format!("{length} from media time {from}");
        if self.rate == 0 {
            s.push_str(", dwell");
        } else if self.rate != 0x10000 {
            s = format!("{s}, rate {}", num(f64::from(self.rate) / 65536.0));
        }
        s
    }
}

const PAGE: u64 = 256;

async fn expand_edits(cx: Cx, e: Edits) -> Result<()> {
    let stride: u64 = if e.wide { 20 } else { 12 };
    let fits = e.span.len.checked_div(stride).unwrap_or(0);
    let count = e.count.min(fits);
    if e.count > fits {
        cx.diag(Diagnostic::truncated(e.span, e.span.len));
    }
    cx.set_count(Count::Exact(count));
    let mut index = 0u64;
    while index < count {
        let n = count.saturating_sub(index).min(PAGE);
        let page = e
            .span
            .sub(index.saturating_mul(stride), n.saturating_mul(stride));
        let d = cx.read(page).await?;
        for j in 0..n {
            let at = to_usize(j.saturating_mul(stride));
            let edit = if e.wide {
                Edit {
                    duration: u64_be(&d, at).unwrap_or(0),
                    media_time: crate::bytes::array(&d, at.saturating_add(8))
                        .map_or(0, i64::from_be_bytes),
                    rate: u32_be(&d, at.saturating_add(16)).unwrap_or(0) as i32,
                }
            } else {
                Edit {
                    duration: u32_be(&d, at).unwrap_or(0).into(),
                    media_time: (u32_be(&d, at.saturating_add(4)).unwrap_or(0) as i32).into(),
                    rate: u32_be(&d, at.saturating_add(8)).unwrap_or(0) as i32,
                }
            };
            let span = page.sub(j.saturating_mul(stride), stride);
            cx.push(
                struct_node(
                    format!("Edit {}", index.saturating_add(j).saturating_add(1)),
                    span,
                    BE,
                    (e.wide, e.movie, e.media),
                    edit_layout,
                )
                .summary(edit.summary(e.movie, e.media)),
            )
            .await;
        }
        index = index.saturating_add(n);
    }
    Ok(())
}

fn edit_layout(f: &mut Fields<'_>, &(wide, movie, media): &(bool, u32, u32)) -> Result<()> {
    f.uword("Segment duration", wide)
        .with(|&d, n| {
            if movie > 0 {
                n.summary(duration(d, movie.into()))
            } else {
                n
            }
        })
        .desc("In movie timescale units")
        .emit()?;
    let time = if wide {
        f.int::<i64>("Media time")
    } else {
        f.i32("Media time").map(i64::from)
    };
    time.with(|&t, n| match u64::try_from(t) {
        Ok(t) if media > 0 => n.summary(duration(t, media.into())),
        _ if t == -1 => n.summary("empty edit"),
        _ => n,
    })
    .desc("Start of the segment in media timescale units; -1 for an empty edit")
    .emit()?;
    f.int::<i16>("Media rate integer").emit()?;
    f.int::<i16>("Media rate fraction").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Packed tables

async fn expand_nibbles(cx: Cx, (span, count): (Span, u64)) -> Result<()> {
    let fits = span.len.saturating_mul(2);
    let count = count.min(fits);
    cx.set_count(Count::Exact(count));
    let mut index = 0u64;
    while index < count {
        let n = count.saturating_sub(index).min(PAGE.saturating_mul(2));
        let page = span.sub(index / 2, n.saturating_add(1) / 2);
        let d = cx.read_avail(page).await?;
        for j in 0..n {
            let byte = d.get(to_usize(j / 2)).copied().unwrap_or(0);
            let v = if j % 2 == 0 { byte >> 4 } else { byte & 15 };
            cx.push(
                Node::new(format!(
                    "Sample {}",
                    index.saturating_add(j).saturating_add(1)
                ))
                .span(page.sub(j / 2, 1))
                .value(Value::UInt {
                    value: v.into(),
                    bits: 4,
                    radix: Radix::Dec,
                }),
            )
            .await;
        }
        index = index.saturating_add(n);
    }
    Ok(())
}

async fn expand_dependencies(cx: Cx, span: Span) -> Result<()> {
    cx.set_count(Count::Exact(span.len));
    let mut index = 0u64;
    while index < span.len {
        let n = span.len.saturating_sub(index).min(PAGE);
        let page = span.sub(index, n);
        let d = cx.read(page).await?;
        for (j, &b) in d.iter().enumerate() {
            let j = to_u64(j);
            let entry = SampleDependency { flags: b };
            let mut node = struct_node(
                SampleDependency::label(index.saturating_add(j)),
                page.sub(j, 1),
                BE,
                (),
                dependency_layout,
            );
            if let Some(s) = entry.summary() {
                node = node.summary(s);
            }
            cx.push(node).await;
        }
        index = index.saturating_add(n);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sample groups

/// Well-known sample grouping types.
pub fn grouping_name(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"roll" => "audio pre-roll / gradual refresh",
        b"prol" => "pre-roll",
        b"rap " => "random access point",
        b"sync" => "sync sample NAL type",
        b"tele" => "temporal level",
        b"seig" => "CENC encryption parameters",
        b"sap " => "stream access point",
        b"alst" => "alternative startup",
        b"tscl" => "temporal layer",
        b"stsa" => "step-wise temporal sub-layer access",
        b"tsas" => "temporal sub-layer access",
        b"scif" => "SVC scalability",
        b"avss" => "AVC sub-sequence",
        b"oinf" => "operating points",
        b"linf" => "layer information",
        b"trif" => "tile region",
        b"nalm" => "NAL unit map",
        b"rash" => "rate share",
        b"dtrt" => "decode retiming",
        b"vipr" => "view priority",
        _ => return None,
    })
}

async fn sgpd(cx: &Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let (v, _) = full_box(&mut f)?;
    let kind = f
        .ascii("Grouping type", 4)
        .with(|t, n| match grouping_name(t.as_bytes()) {
            Some(s) => n.summary(s),
            None => n,
        })
        .emit()?;
    let mut default_length = 0u32;
    if v == 1 {
        default_length = f
            .u32("Default length")
            .desc("0 = each entry starts with its length")
            .emit()?;
    }
    if v >= 2 {
        f.u32("Default sample description index").emit()?;
    }
    let n = f.u32("Entry count").emit()?;
    let mut raw = [0u8; 4];
    for (slot, b) in raw
        .iter_mut()
        .zip(kind.bytes().chain(std::iter::repeat(b' ')))
    {
        *slot = b;
    }
    for i in 0..n {
        if f.remaining() == 0 {
            break;
        }
        if i & 0xff == 0xff {
            cx.checkpoint().await;
        }
        let start = f.pos();
        let mut len = if v == 1 && default_length == 0 {
            let mut silent = Fields::new(&block, BE);
            silent.seek(start);
            Some(u64::from(silent.u32("Length").get()?).saturating_add(4))
        } else if v == 1 {
            Some(u64::from(default_length))
        } else {
            None
        };
        if len.is_none() {
            len = group_entry_len(&raw, &block.data, to_usize(start));
        }
        let Some(len) = len.filter(|&l| l > 0) else {
            let rest = f.remaining();
            f.bytes("Entries", rest)
                .desc("Entry sizes are unknown for this grouping type in version 0")
                .emit()?;
            break;
        };
        let span = body.sub(start, len);
        let data = block
            .data
            .get(to_usize(start)..to_usize(start.saturating_add(len)))
            .unwrap_or_default();
        let lead = if v == 1 && default_length == 0 { 4 } else { 0 };
        let mut node = struct_node(
            format!("Entry {}", i.saturating_add(1)),
            span,
            BE,
            (raw, lead),
            group_entry,
        );
        if let Some(s) = group_summary(&raw, data.get(lead..).unwrap_or_default()) {
            node = node.summary(s);
        }
        cx.emit(node);
        f.skip(len);
    }
    Ok(())
}

/// The size of a version-0 group description entry, for known types.
fn group_entry_len(kind: &[u8; 4], d: &[u8], at: usize) -> Option<u64> {
    Some(match kind {
        b"roll" | b"prol" => 2,
        b"rap " | b"sync" | b"tele" | b"sap " => 1,
        b"seig" => {
            let protected = *d.get(at.saturating_add(2))?;
            let iv = *d.get(at.saturating_add(3))?;
            if protected == 1 && iv == 0 {
                let n = *d.get(at.saturating_add(20))?;
                21u64.saturating_add(n.into())
            } else {
                20
            }
        }
        _ => return None,
    })
}

fn group_summary(kind: &[u8; 4], d: &[u8]) -> Option<String> {
    match kind {
        b"roll" | b"prol" => {
            let n = i16::from_be_bytes(crate::bytes::array(d, 0)?);
            Some(format!("roll distance {n}"))
        }
        b"sync" => Some(format!("NAL unit type {}", d.first()? & 0x3f)),
        b"rap " => {
            let b = *d.first()?;
            Some(if b & 0x80 != 0 {
                format!("{} leading samples", b & 0x7f)
            } else {
                "leading samples unknown".to_owned()
            })
        }
        b"sap " => Some(format!("SAP type {}", d.first()? & 15)),
        b"tele" => Some(if d.first()? & 0x80 != 0 {
            "independently decodable level".to_owned()
        } else {
            "not independently decodable".to_owned()
        }),
        b"seig" => {
            let protected = *d.get(2)?;
            let iv = *d.get(3)?;
            Some(if protected == 0 {
                "not protected".to_owned()
            } else {
                format!("{iv}-byte IVs, KID {}", uuid(d.get(4..20)?))
            })
        }
        _ => None,
    }
}

fn group_entry(f: &mut Fields<'_>, &(kind, lead): &([u8; 4], usize)) -> Result<()> {
    if lead > 0 {
        f.u32("Description length").emit()?;
    }
    match &kind {
        b"roll" | b"prol" => {
            f.int::<i16>("Roll distance")
                .desc("Samples to decode before (negative) or after this one for a correct output")
                .emit()?;
        }
        b"sync" => {
            f.u8("NAL unit type")
                .with(|&v, n| n.summary(format!("{}", v & 0x3f)))
                .emit()?;
        }
        b"rap " => {
            f.u8("Leading samples")
                .hex()
                .with(|&v, n| {
                    n.summary(if v & 0x80 != 0 {
                        format!("{} known", v & 0x7f)
                    } else {
                        "unknown".to_owned()
                    })
                })
                .emit()?;
        }
        b"sap " => {
            f.u8("SAP")
                .hex()
                .with(|&v, n| {
                    n.summary(format!(
                        "type {}{}",
                        v & 15,
                        if v & 0x80 != 0 { ", dependent" } else { "" }
                    ))
                })
                .emit()?;
        }
        b"tele" => {
            f.u8("Level independently decodable").hex().emit()?;
        }
        b"seig" => {
            f.u8("Reserved").emit()?;
            f.u8("Crypt/skip byte blocks")
                .with(|&b, n| n.summary(format!("crypt {}, skip {}", b >> 4, b & 15)))
                .emit()?;
            let protected = f.u8("Is protected").emit()?;
            let iv = f.u8("Per-sample IV size").emit()?;
            let kid = f.bytes("KID", 16);
            let span = kid.span();
            let kid = kid.get()?;
            f.node(text("KID", span, uuid(&kid)));
            if protected == 1 && iv == 0 {
                let n = f.u8("Constant IV size").emit()?;
                f.bytes("Constant IV", n.into()).emit()?;
            }
        }
        _ => {}
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Data", rest).emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Common encryption: sample auxiliary information

async fn senc(cx: &Cx, body: Span) -> Result<()> {
    let (flags, count) = header(cx, body, |f| {
        let (_, flags) = super::full_box_flags(f, SENC_FLAGS)?;
        let n = f.u32("Sample count").emit()?;
        Ok((flags, n))
    })
    .await?;
    let entries = body.tail(8);
    let subsamples = flags & 2 != 0;
    let data = read_small(cx, entries, 0x10_0000).await?;
    let iv = infer_iv_size(cx, &data, count.into(), subsamples).await;
    let mut node = Node::new("Samples")
        .span(entries)
        .summary(plural(count, "sample"));
    match iv {
        Some(iv) => {
            node = node
                .summary(format!("{}, {iv}-byte IVs", plural(count, "sample")))
                .desc("The IV size comes from 'tenc' or 'seig'; here it is inferred from the box size")
                .lazy(expand_senc, (entries, u64::from(count), iv, subsamples));
        }
        None => {
            node = node.diag(Diagnostic::note("IV size could not be inferred"));
        }
    }
    cx.emit(node);
    Ok(())
}

const SENC_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x1, "OVERRIDE_TRACK_ENCRYPTION"),
    crate::value::flag(0x2, "USE_SUBSAMPLE_ENCRYPTION"),
];

/// The per-sample IV size that makes the entries fill `data` exactly.
async fn infer_iv_size(cx: &Cx, data: &[u8], count: u64, subsamples: bool) -> Option<u64> {
    for iv in [8u64, 16, 0] {
        if iv == 0 && !subsamples {
            if data.is_empty() {
                return Some(0);
            }
            continue;
        }
        let mut at = 0u64;
        let mut ok = true;
        for i in 0..count {
            at = at.saturating_add(iv);
            if subsamples {
                let Some(n) = u16_be(data, to_usize(at)) else {
                    ok = false;
                    break;
                };
                at = at
                    .saturating_add(2)
                    .saturating_add(u64::from(n).saturating_mul(6));
            }
            if at > to_u64(data.len()) {
                ok = false;
                break;
            }
            if i & 0xfff == 0xfff {
                cx.checkpoint().await;
            }
        }
        if ok && at == to_u64(data.len()) {
            return Some(iv);
        }
    }
    None
}

async fn expand_senc(cx: Cx, (span, count, iv, subsamples): (Span, u64, u64, bool)) -> Result<()> {
    let data = read_small(&cx, span, 0x10_0000).await?;
    let mut at = 0u64;
    for i in 0..count {
        let start = at;
        let mut n = 0u16;
        at = at.saturating_add(iv);
        if subsamples {
            n = u16_be(&data, to_usize(at)).unwrap_or(0);
            at = at
                .saturating_add(2)
                .saturating_add(u64::from(n).saturating_mul(6));
        }
        if at > to_u64(data.len()) {
            break;
        }
        let entry = span.sub(start, at.saturating_sub(start));
        let iv_bytes = data
            .get(to_usize(start)..to_usize(start.saturating_add(iv)))
            .unwrap_or_default();
        let mut summary = if iv_bytes.is_empty() {
            "no IV".to_owned()
        } else {
            format!(
                "IV {}",
                iv_bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        };
        if subsamples {
            summary = format!("{summary}, {}", plural(n, "subsample"));
        }
        cx.push(
            struct_node(
                format!("Sample {}", i.saturating_add(1)),
                entry,
                BE,
                (iv, subsamples),
                senc_entry,
            )
            .summary(summary),
        )
        .await;
    }
    Ok(())
}

fn senc_entry(f: &mut Fields<'_>, &(iv, subsamples): &(u64, bool)) -> Result<()> {
    if iv > 0 {
        f.bytes("Initialization vector", iv).emit()?;
    }
    if subsamples {
        let n = f.u16("Subsample count").emit()?;
        for _ in 0..n {
            let at = f.peek_span(6);
            let clear = f.u16("Clear bytes").get()?;
            let protected = f.u32("Protected bytes").get()?;
            f.node(
                struct_node("Subsample", at, BE, (), subsample)
                    .summary(format!("{clear} clear, {protected} encrypted bytes")),
            );
        }
    }
    Ok(())
}

fn subsample(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Clear bytes").emit()?;
    f.u32("Protected bytes").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Track fragment random access

#[derive(Clone, Copy, Debug)]
struct Tfra {
    span: Span,
    count: u64,
    wide: bool,
    traf: u64,
    trun: u64,
    sample: u64,
}

async fn expand_tfra(cx: Cx, t: Tfra) -> Result<()> {
    let word: u64 = if t.wide { 8 } else { 4 };
    let stride = word
        .saturating_mul(2)
        .saturating_add(t.traf)
        .saturating_add(t.trun)
        .saturating_add(t.sample);
    let fits = t.span.len.checked_div(stride).unwrap_or(0);
    let count = t.count.min(fits);
    cx.set_count(Count::Exact(count));
    let mut index = 0u64;
    while index < count {
        let n = count.saturating_sub(index).min(PAGE);
        let page = t
            .span
            .sub(index.saturating_mul(stride), n.saturating_mul(stride));
        let d = cx.read(page).await?;
        for j in 0..n {
            let at = to_usize(j.saturating_mul(stride));
            let get = |at: usize, len: u64| {
                d.get(at..at.saturating_add(to_usize(len)))
                    .map_or(0u64, |b| {
                        b.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x))
                    })
            };
            let w = to_usize(word);
            let time = get(at, word);
            let offset = get(at.saturating_add(w), word);
            cx.push(
                struct_node(
                    format!("Entry {}", index.saturating_add(j).saturating_add(1)),
                    page.sub(j.saturating_mul(stride), stride),
                    BE,
                    t,
                    tfra_entry,
                )
                .summary(format!("time {time}, moof at {offset:#x}")),
            )
            .await;
        }
        index = index.saturating_add(n);
    }
    Ok(())
}

fn tfra_entry(f: &mut Fields<'_>, t: &Tfra) -> Result<()> {
    f.uword("Time", t.wide).emit()?;
    f.uword("moof offset", t.wide).hex().emit()?;
    for (name, len) in [
        ("traf number", t.traf),
        ("trun number", t.trun),
        ("Sample number", t.sample),
    ] {
        let at = f.peek_span(len);
        let v = f.bytes(name, len).get()?;
        let v = v.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
        f.node(crate::formats::util::vidutil::uint(name, at, v, 32));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Track fragment runs

fn trun_stride(flags: u32) -> u64 {
    u64::from((flags & 0xf00).count_ones()).saturating_mul(4)
}

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
