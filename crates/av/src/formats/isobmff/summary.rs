//! One-line summaries: per track, and for the file node ("MP4 (isom),
//! 1:23.45, H.264 1920×1080 29.97 fps + AAC-LC stereo 48 kHz").

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::Input;
use crate::formats::util::vidutil::{fourcc, plural};
use crate::span::Span;

use super::boxes::{bitrate, handler_name, matrix_at, short_language, transform};
use super::sample::{CodecInfo, EntryKind, codec_info};
use super::tables::fps;
use super::{BoxState, Brand, find_child, find_path, read_header, small};

/// The handler type of a `trak` or `mdia` box body.
pub async fn handler_of(cx: &Cx, kind: &[u8; 4], body: Span) -> Option<[u8; 4]> {
    let mdia = if kind == b"trak" {
        find_path(cx, body, &[b"mdia"]).await.ok()??
    } else {
        body
    };
    let hdlr = find_path(cx, mdia, &[b"hdlr"]).await.ok()??;
    let d = cx.read_avail(hdlr.sub(8, 4)).await.ok()?;
    crate::bytes::array(&d, 0)
}

/// The timescale of the `mvhd` or `mdhd` at `path` under `region`.
pub async fn timescale(cx: &Cx, region: Span, path: &[&[u8; 4]]) -> Option<u32> {
    let body = find_path(cx, region, path).await.ok()??;
    let d = cx.read_avail(body.sub(0, 24)).await.ok()?;
    let at = if d.first() == Some(&1) { 20 } else { 12 };
    u32_be(&d, at).filter(|&t| t > 0)
}

/// A playing time for summaries: "0:00.20", "1:23.45", "1:02:03.04".
pub fn short_duration(units: u64, timescale: u32) -> String {
    if units == u64::MAX || units == u64::from(u32::MAX) {
        return "indefinite".to_owned();
    }
    let hundredths = u128::from(units)
        .saturating_mul(100)
        .checked_div(u128::from(timescale))
        .unwrap_or(0);
    let hundredths = u64::try_from(hundredths).unwrap_or(u64::MAX);
    let cs = hundredths % 100;
    let secs = hundredths / 100;
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}.{cs:02}")
    } else {
        format!("{m}:{s:02}.{cs:02}")
    }
}

#[derive(Clone, Debug, Default)]
pub struct TrackInfo {
    pub id: u32,
    pub handler: [u8; 4],
    pub enabled: bool,
    pub width: u32,
    pub height: u32,
    pub transform: Option<String>,
    pub duration: u64,
    pub timescale: u32,
    pub language: Option<String>,
    pub codec: Option<CodecInfo>,
    pub samples: u64,
    /// The single `stts` delta, when all samples last equally long.
    pub delta: Option<u32>,
    pub total_bytes: Option<u64>,
    pub timecode: Option<String>,
}

impl TrackInfo {
    fn is_video(&self) -> bool {
        self.codec
            .as_ref()
            .is_some_and(|c| c.kind == EntryKind::Visual)
            && self.handler != *b"pict"
    }

    /// Frames per second, for video.
    pub fn fps(&self) -> Option<f64> {
        if !self.is_video() || self.timescale == 0 {
            return None;
        }
        if let Some(d) = self.delta.filter(|&d| d > 0) {
            return Some(f64::from(self.timescale) / f64::from(d));
        }
        (self.samples > 0 && self.duration > 0)
            .then(|| self.samples as f64 * f64::from(self.timescale) / self.duration as f64)
    }

    /// Average bits per second: as the codec declares it, else from the
    /// sample sizes.
    pub fn bitrate(&self) -> Option<u64> {
        if let Some(b) = self.codec.as_ref().and_then(|c| c.bitrate) {
            return Some(b);
        }
        if let Some(total) = self.total_bytes
            && self.duration > 0
            && self.timescale > 0
        {
            let bps = u128::from(total)
                .saturating_mul(8)
                .saturating_mul(u128::from(self.timescale))
                .checked_div(u128::from(self.duration))
                .unwrap_or(0);
            return u64::try_from(bps).ok();
        }
        None
    }

    pub fn describe(&self) -> String {
        let kind = handler_name(&self.handler).map_or_else(|| fourcc(&self.handler), str::to_owned);
        let mut parts = Vec::new();
        if let Some(c) = &self.codec {
            parts.push(c.describe());
        } else if self.width > 0 && self.height > 0 {
            parts.push(format!("{}×{}", self.width, self.height));
        }
        if let Some(t) = &self.timecode {
            parts.push(format!("starts at {t}"));
        }
        if let Some(r) = self.fps() {
            parts.push(format!("{} fps", fps(r)));
        }
        if let Some(b) = self.bitrate().filter(|&b| b > 0) {
            parts.push(bitrate(b));
        }
        if self.timescale > 0 {
            parts.push(short_duration(self.duration, self.timescale));
        }
        if let Some(l) = &self.language {
            parts.push(l.clone());
        }
        if let Some(t) = &self.transform {
            parts.push(t.clone());
        }
        if !self.enabled {
            parts.push("disabled".to_owned());
        }
        format!("{kind} track {}: {}", self.id, parts.join(", "))
    }

    /// The part of the file summary for this track.
    fn short(&self) -> Option<String> {
        if let Some(t) = &self.timecode {
            return Some(format!("timecode {t}"));
        }
        let c = self.codec.as_ref()?;
        let mut s = c.short();
        if let Some(r) = self.fps() {
            s = format!("{s} {} fps", fps(r));
        }
        if c.kind == EntryKind::Other
            && let Some(l) = &self.language
        {
            s = format!("{s} ({l})");
        }
        Some(s)
    }
}

/// Collects what a track says about itself from a few small reads.
pub async fn track(cx: &Cx, input: Input, brand: Brand, trak: Span) -> Result<TrackInfo> {
    let mut info = TrackInfo::default();
    if let Some(tkhd) = find_path(cx, trak, &[b"tkhd"]).await? {
        let d = small(cx, tkhd.sub(0, 92)).await?;
        let wide = d.first() == Some(&1);
        info.enabled = u32_be(&d, 0).is_some_and(|f| f & 1 != 0);
        info.id = u32_be(&d, if wide { 20 } else { 12 }).unwrap_or(0);
        let dims = if wide { 88 } else { 76 };
        info.width = u32_be(&d, dims).unwrap_or(0) >> 16;
        info.height = u32_be(&d, dims.saturating_add(4)).unwrap_or(0) >> 16;
        if let Some(m) = matrix_at(&d, if wide { 52 } else { 40 }) {
            let t = transform(&m);
            if t != "identity" {
                info.transform = Some(t);
            }
        }
    }
    let Some(mdia) = find_path(cx, trak, &[b"mdia"]).await? else {
        return Ok(info);
    };
    if let Some(mdhd) = find_path(cx, mdia, &[b"mdhd"]).await? {
        let d = small(cx, mdhd.sub(0, 36)).await?;
        let wide = d.first() == Some(&1);
        let at = if wide { 20 } else { 12 };
        info.timescale = u32_be(&d, at).unwrap_or(0);
        info.duration = if wide {
            u64_be(&d, at.saturating_add(4)).unwrap_or(0)
        } else {
            u32_be(&d, at.saturating_add(4)).map_or(0, u64::from)
        };
        info.language =
            u16_be(&d, at.saturating_add(if wide { 12 } else { 8 })).and_then(short_language);
    }
    if let Some(hdlr) = find_path(cx, mdia, &[b"hdlr"]).await? {
        let d = cx.read_avail(hdlr.sub(8, 4)).await?;
        info.handler = crate::bytes::array(&d, 0).unwrap_or_default();
    }
    let Some(stbl) = find_path(cx, mdia, &[b"minf", b"stbl"]).await? else {
        return Ok(info);
    };
    if let Some(stsd) = find_path(cx, stbl, &[b"stsd"]).await?
        && let Some(h) = read_header(cx, stsd, 0).await?
    {
        let d = small(
            cx,
            stsd.sub(h.header_len, h.size.saturating_sub(h.header_len)),
        )
        .await?;
        info.codec = Some(codec_info(&h.kind, &info.handler, brand, &d));
    }
    if let Some(stsz) = find_path(cx, stbl, &[b"stsz"]).await? {
        let d = small(cx, stsz.sub(0, 12)).await?;
        let size = u32_be(&d, 4).unwrap_or(0);
        info.samples = u32_be(&d, 8).unwrap_or(0).into();
        if size > 0 {
            info.total_bytes = Some(u64::from(size).saturating_mul(info.samples));
        } else if info.samples <= 0x4000 {
            let table = small(cx, stsz.sub(12, info.samples.saturating_mul(4))).await?;
            if to_u64(table.len()) == info.samples.saturating_mul(4) {
                info.total_bytes = Some(table.as_chunks::<4>().0.iter().fold(0u64, |acc, c| {
                    acc.saturating_add(u32::from_be_bytes(*c).into())
                }));
            }
        }
    }
    if let Some(stts) = find_path(cx, stbl, &[b"stts"]).await? {
        let d = small(cx, stts.sub(0, 16)).await?;
        if u32_be(&d, 4) == Some(1) {
            info.delta = u32_be(&d, 12);
        }
    }
    if let Some(tc) = info.codec.as_ref().and_then(|c| c.timecode) {
        let offset = match find_path(cx, stbl, &[b"stco"]).await? {
            Some(stco) => {
                let d = small(cx, stco.sub(0, 12)).await?;
                u32_be(&d, 8).map(u64::from)
            }
            None => match find_path(cx, stbl, &[b"co64"]).await? {
                Some(co64) => {
                    let d = small(cx, co64.sub(0, 16)).await?;
                    u64_be(&d, 8)
                }
                None => None,
            },
        };
        if let Some(offset) = offset {
            let d = cx.read_avail(input.span.sub(offset, 4)).await?;
            if let Some(frame) = u32_be(&d, 0) {
                info.timecode = Some(tc.format(frame));
            }
        }
    }
    Ok(info)
}

/// Builds the file node's summary while the top level is walked.
#[derive(Default)]
pub struct Annotation {
    major: Option<String>,
    image: Option<String>,
    tracks: Vec<TrackInfo>,
    /// Movie duration and timescale (`mvhd`, or `mehd` when fragmented).
    movie: Option<(u64, u32)>,
    fragmented: bool,
    /// Default sample durations from `trex`: (track ID, duration).
    defaults: Vec<(u32, u32)>,
    /// The end of each track's fragments so far: (track ID, end time).
    ends: Vec<(u32, u64)>,
    /// `mehd` was present: the movie duration is known up front.
    declared: bool,
}

impl Annotation {
    pub async fn observe(&mut self, cx: &Cx, st: &BoxState) {
        let body = st.body();
        let brand = st.ctx.brand;
        match &st.header.kind {
            b"ftyp" => {
                if let Ok(d) = cx.read_avail(body.sub(0, 4)).await {
                    self.major = Some(fourcc(&d).trim_end().to_owned());
                }
            }
            b"moov" => {
                let _ = self.movie(cx, st.input, brand, body).await;
            }
            b"meta" if matches!(brand, Brand::Heif | Brand::Avif) => {
                self.image = super::heif::summary(cx, body.tail(4)).await.ok().flatten();
            }
            b"jp2h" => self.image = jp2_header(cx, body).await,
            b"moof" => {
                self.fragmented = true;
                let _ = self.fragment(cx, body).await;
            }
            _ => return,
        }
        cx.annotate(self.render(brand));
    }

    fn render(&self, brand: Brand) -> String {
        let mut s = brand.label().to_owned();
        if let Some(m) = &self.major {
            s = format!("{s} ({m})");
        }
        let mut parts = vec![s];
        if let Some(i) = &self.image {
            parts.push(i.clone());
        }
        if let Some(d) = self.duration() {
            parts.push(d);
        }
        let any_enabled = self.tracks.iter().any(|t| t.enabled);
        let tracks: Vec<String> = self
            .tracks
            .iter()
            .filter(|t| t.enabled || !any_enabled)
            .filter_map(TrackInfo::short)
            .collect();
        if !tracks.is_empty() {
            parts.push(tracks.join(" + "));
        }
        if self.fragmented {
            parts.push("fragmented".to_owned());
        }
        parts.join(", ")
    }

    fn duration(&self) -> Option<String> {
        if self.fragmented && !self.declared {
            // The longest track, from the fragments seen so far.
            let mut best: Option<(u64, u32)> = None;
            for (id, end) in &self.ends {
                let Some(t) = self.tracks.iter().find(|t| t.id == *id) else {
                    continue;
                };
                if t.timescale == 0 {
                    continue;
                }
                let longer = best.is_none_or(|(e, ts)| {
                    u128::from(*end).saturating_mul(u128::from(ts))
                        > u128::from(e).saturating_mul(u128::from(t.timescale))
                });
                if longer {
                    best = Some((*end, t.timescale));
                }
            }
            if let Some((end, ts)) = best {
                return Some(short_duration(end, ts));
            }
        }
        if let Some((units, ts)) = self.movie
            && units > 0
            && ts > 0
            && units != u64::MAX
            && units != u64::from(u32::MAX)
        {
            return Some(short_duration(units, ts));
        }
        // An indefinite or missing movie duration: the longest track.
        let (units, ts) = self
            .tracks
            .iter()
            .filter(|t| t.timescale > 0 && t.duration > 0)
            .map(|t| (t.duration, t.timescale))
            .max_by(|a, b| {
                (u128::from(a.0).saturating_mul(u128::from(b.1)))
                    .cmp(&u128::from(b.0).saturating_mul(u128::from(a.1)))
            })?;
        Some(short_duration(units, ts))
    }

    async fn movie(&mut self, cx: &Cx, input: Input, brand: Brand, moov: Span) -> Result<()> {
        let mut pos = 0u64;
        let mut count = 0u32;
        self.tracks.clear();
        while let Some(h) = read_header(cx, moov, pos).await? {
            if &h.kind == b"trak" {
                let t = track(cx, input, brand, moov.sub(pos, h.size).tail(h.header_len)).await?;
                self.tracks.push(t);
            }
            pos = pos.saturating_add(h.size);
            count = count.saturating_add(1);
            if count > 256 || h.to_end {
                break;
            }
        }
        let movie_ts = timescale(cx, moov, &[b"mvhd"]).await.unwrap_or(0);
        if let Some(mvhd) = find_path(cx, moov, &[b"mvhd"]).await? {
            let d = small(cx, mvhd.sub(0, 32)).await?;
            let wide = d.first() == Some(&1);
            let at = if wide { 24 } else { 16 };
            let dur = if wide {
                u64_be(&d, at)
            } else {
                u32_be(&d, at).map(u64::from)
            };
            if let Some(dur) = dur {
                self.movie = Some((dur, movie_ts));
            }
        }
        if let Some(mvex) = find_path(cx, moov, &[b"mvex"]).await? {
            let mut pos = 0u64;
            let mut count = 0u32;
            while let Some(h) = read_header(cx, mvex, pos).await? {
                let body = mvex.sub(pos, h.size).tail(h.header_len);
                match &h.kind {
                    b"trex" => {
                        let d = small(cx, body.sub(0, 16)).await?;
                        if let (Some(id), Some(dur)) = (u32_be(&d, 4), u32_be(&d, 12)) {
                            self.defaults.push((id, dur));
                        }
                    }
                    b"mehd" => {
                        let d = small(cx, body.sub(0, 12)).await?;
                        let dur = if d.first() == Some(&1) {
                            u64_be(&d, 4)
                        } else {
                            u32_be(&d, 4).map(u64::from)
                        };
                        if let Some(dur) = dur.filter(|&d| d > 0) {
                            self.movie = Some((dur, movie_ts));
                            self.declared = true;
                        }
                    }
                    _ => {}
                }
                pos = pos.saturating_add(h.size);
                count = count.saturating_add(1);
                if count > 256 || h.to_end {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Extends the tracks' fragment end times with one `moof`.
    async fn fragment(&mut self, cx: &Cx, moof: Span) -> Result<()> {
        let mut pos = 0u64;
        let mut count = 0u32;
        while let Some(h) = read_header(cx, moof, pos).await? {
            if &h.kind == b"traf" {
                self.traf(cx, moof.sub(pos, h.size).tail(h.header_len))
                    .await?;
            }
            pos = pos.saturating_add(h.size);
            count = count.saturating_add(1);
            if count > 256 || h.to_end {
                break;
            }
        }
        Ok(())
    }

    async fn traf(&mut self, cx: &Cx, traf: Span) -> Result<()> {
        let Some((h, tfhd)) = find_child(cx, traf, b"tfhd").await? else {
            return Ok(());
        };
        let d = small(cx, tfhd.tail(h.header_len).sub(0, 40)).await?;
        let flags = u32_be(&d, 0).unwrap_or(0) & 0x00ff_ffff;
        let Some(id) = u32_be(&d, 4) else {
            return Ok(());
        };
        let mut at = 8usize;
        if flags & 1 != 0 {
            at = at.saturating_add(8);
        }
        if flags & 2 != 0 {
            at = at.saturating_add(4);
        }
        let default = if flags & 8 != 0 {
            u32_be(&d, at)
        } else {
            self.defaults
                .iter()
                .find(|(t, _)| *t == id)
                .map(|(_, dur)| *dur)
        }
        .unwrap_or(0);
        let previous = self.ends.iter().find(|(t, _)| *t == id).map(|(_, e)| *e);
        let mut time = match find_child(cx, traf, b"tfdt").await? {
            Some((h, tfdt)) => {
                let d = small(cx, tfdt.tail(h.header_len).sub(0, 12)).await?;
                if d.first() == Some(&1) {
                    u64_be(&d, 4)
                } else {
                    u32_be(&d, 4).map(u64::from)
                }
            }
            None => None,
        }
        .or(previous)
        .unwrap_or(0);
        let mut pos = 0u64;
        let mut count = 0u32;
        while let Some(h) = read_header(cx, traf, pos).await? {
            if &h.kind == b"trun" {
                let body = traf.sub(pos, h.size).tail(h.header_len);
                time = time.saturating_add(run_duration(cx, body, default).await?);
            }
            pos = pos.saturating_add(h.size);
            count = count.saturating_add(1);
            if count > 256 || h.to_end {
                break;
            }
        }
        match self.ends.iter_mut().find(|(t, _)| *t == id) {
            Some(slot) => slot.1 = slot.1.max(time),
            None => self.ends.push((id, time)),
        }
        Ok(())
    }
}

/// The total duration of a `trun`'s samples.
async fn run_duration(cx: &Cx, trun: Span, default: u32) -> Result<u64> {
    let d = small(cx, trun).await?;
    let flags = u32_be(&d, 0).unwrap_or(0) & 0x00ff_ffff;
    let n = u64::from(u32_be(&d, 4).unwrap_or(0));
    if flags & 0x100 == 0 {
        return Ok(n.saturating_mul(default.into()));
    }
    let mut at = 8usize;
    if flags & 1 != 0 {
        at = at.saturating_add(4);
    }
    if flags & 4 != 0 {
        at = at.saturating_add(4);
    }
    let stride = to_usize(u64::from((flags & 0xf00).count_ones()).saturating_mul(4));
    let mut total = 0u64;
    let mut i = 0u64;
    while i < n {
        let Some(v) = u32_be(&d, at) else { break };
        total = total.saturating_add(v.into());
        at = at.saturating_add(stride);
        i = i.saturating_add(1);
        if i & 0xfff == 0 {
            cx.checkpoint().await;
        }
    }
    Ok(total)
}

async fn jp2_header(cx: &Cx, jp2h: Span) -> Option<String> {
    let (h, span) = find_child(cx, jp2h, b"ihdr").await.ok()??;
    let d = cx
        .read_avail(span.tail(h.header_len).sub(0, 11))
        .await
        .ok()?;
    Some(format!(
        "{}×{}, {}",
        u32_be(&d, 4)?,
        u32_be(&d, 0)?,
        plural(u16_be(&d, 8)?, "component")
    ))
}
