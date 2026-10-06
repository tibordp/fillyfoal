//! One-line summaries: per track, and for the file node ("MP4 (isom),
//! 1920×1080 H.264 + AAC, 00:01:23.000").

use crate::bytes::{u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::vidutil::{duration, fourcc};
use crate::span::Span;

use super::boxes::{handler_name, language};
use super::sample::{EntryInfo, entry_info};
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

#[derive(Clone, Debug, Default)]
pub struct TrackInfo {
    pub id: u32,
    pub handler: [u8; 4],
    pub width: u32,
    pub height: u32,
    pub duration: u64,
    pub timescale: u32,
    pub language: Option<String>,
    pub entry: Option<EntryInfo>,
}

impl TrackInfo {
    pub fn describe(&self) -> String {
        let kind = handler_name(&self.handler).map_or_else(|| fourcc(&self.handler), str::to_owned);
        let mut s = format!("{kind} track {}", self.id);
        if let Some(e) = &self.entry {
            s = format!("{s}: {}", e.describe());
        } else if self.width > 0 && self.height > 0 {
            s = format!("{s}: {}×{}", self.width, self.height);
        }
        if self.timescale > 0 {
            s = format!("{s}, {}", duration(self.duration, self.timescale.into()));
        }
        if let Some(l) = &self.language
            && l != "und"
        {
            s = format!("{s}, {l}");
        }
        s
    }

    /// The codec part of the file summary ("1920×1080 H.264", "AAC").
    fn short(&self) -> Option<String> {
        let e = self.entry.as_ref()?;
        let codec = e.codec.map_or_else(|| e.fourcc.clone(), str::to_owned);
        Some(if e.width > 0 && e.height > 0 {
            format!("{}×{} {codec}", e.width, e.height)
        } else {
            codec
        })
    }
}

/// Collects what a track says about itself from a few small reads.
pub async fn track(cx: &Cx, trak: Span) -> Result<TrackInfo> {
    let mut info = TrackInfo::default();
    if let Some(tkhd) = find_path(cx, trak, &[b"tkhd"]).await? {
        let d = small(cx, tkhd.sub(0, 92)).await?;
        let wide = d.first() == Some(&1);
        info.id = u32_be(&d, if wide { 20 } else { 12 }).unwrap_or(0);
        let dims = if wide { 88 } else { 76 };
        info.width = u32_be(&d, dims).unwrap_or(0) >> 16;
        info.height = u32_be(&d, dims.saturating_add(4)).unwrap_or(0) >> 16;
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
        info.language = u16_be(&d, at.saturating_add(if wide { 12 } else { 8 }))
            .map(|l| language(l & 0x7fff));
    }
    if let Some(hdlr) = find_path(cx, mdia, &[b"hdlr"]).await? {
        let d = cx.read_avail(hdlr.sub(8, 4)).await?;
        info.handler = crate::bytes::array(&d, 0).unwrap_or_default();
    }
    if let Some(stsd) = find_path(cx, mdia, &[b"minf", b"stbl", b"stsd"]).await?
        && let Some(h) = read_header(cx, stsd, 0).await?
    {
        let d = small(cx, stsd.sub(h.header_len, 64)).await?;
        info.entry = Some(entry_info(&h.kind, &info.handler, &d));
    }
    Ok(info)
}

/// Builds the file node's summary while the top level is walked.
#[derive(Default)]
pub struct Annotation {
    major: Option<String>,
    details: Option<String>,
    fragmented: bool,
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
            b"moov" => self.details = movie(cx, body).await.ok().flatten(),
            b"meta" if matches!(brand, Brand::Heif | Brand::Avif) => {
                self.details = super::heif::summary(cx, body.tail(4)).await.ok().flatten();
            }
            b"jp2h" => self.details = jp2_header(cx, body).await,
            b"moof" => {
                if self.fragmented {
                    return;
                }
                self.fragmented = true;
            }
            _ => return,
        }
        let mut s = brand.label().to_owned();
        if let Some(m) = &self.major {
            s = format!("{s} ({m})");
        }
        if let Some(d) = &self.details {
            s = format!("{s}, {d}");
        }
        if self.fragmented {
            s.push_str(", fragmented");
        }
        cx.annotate(s);
    }
}

async fn movie(cx: &Cx, moov: Span) -> Result<Option<String>> {
    let mut parts = Vec::new();
    let mut pos = 0u64;
    let mut count = 0u32;
    while let Some(h) = read_header(cx, moov, pos).await? {
        if &h.kind == b"trak" {
            let t = track(cx, moov.sub(pos, h.size).tail(h.header_len)).await?;
            if let Some(s) = t.short() {
                parts.push(s);
            }
        }
        pos = pos.saturating_add(h.size);
        count = count.saturating_add(1);
        if count > 64 {
            break;
        }
    }
    let mut s = parts.join(" + ");
    if let Some(mvhd) = find_path(cx, moov, &[b"mvhd"]).await? {
        let d = small(cx, mvhd.sub(0, 32)).await?;
        let wide = d.first() == Some(&1);
        let at = if wide { 20 } else { 12 };
        let timescale = u32_be(&d, at).unwrap_or(0);
        let dur = if wide {
            u64_be(&d, at.saturating_add(4))
        } else {
            u32_be(&d, at.saturating_add(4)).map(u64::from)
        };
        if let Some(dur) = dur
            && timescale > 0
            && dur > 0
        {
            let d = duration(dur, timescale.into());
            s = if s.is_empty() { d } else { format!("{s}, {d}") };
        }
    }
    Ok((!s.is_empty()).then_some(s))
}

async fn jp2_header(cx: &Cx, jp2h: Span) -> Option<String> {
    let (h, span) = find_child(cx, jp2h, b"ihdr").await.ok()??;
    let d = cx.read_avail(span.tail(h.header_len).sub(0, 11)).await.ok()?;
    Some(format!(
        "{}×{}, {} components",
        u32_be(&d, 4)?,
        u32_be(&d, 0)?,
        u16_be(&d, 8)?
    ))
}
