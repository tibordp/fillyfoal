//! Material Exchange Format (SMPTE 377M): a sequence of KLV triplets (16-byte
//! SMPTE universal label, BER length, value). Partition packs, the primer
//! pack, header metadata sets (local sets with 2-byte tags), index table
//! segments and essence elements are named; partition packs and metadata
//! sets are decoded. KLVs are listed in pages.

use crate::bytes::{to_u64, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::vidutil::{self, text, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const BE: Endian = Endian::Big;

const PARTITION_PREFIX: &[u8] = b"\x06\x0e\x2b\x34\x02\x05\x01\x01\x0d\x01\x02\x01\x01";

pub static FORMAT: Format = Format {
    name: "mxf",
    title: "Material Exchange Format",
    extensions: &["mxf"],
    mime: "application/mxf",
    probe: Probe::Custom(|h| {
        h.starts_with(PARTITION_PREFIX) && h.data.get(13).is_some_and(|&k| (2..=4).contains(&k))
    }),
    dissect: crate::expander!(dissect: Input),
};

/// What a key is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Partition,
    Primer,
    Set,
    Index,
    RandomIndex,
    Fill,
    Essence,
    Other,
}

fn classify(k: &[u8]) -> (Kind, String) {
    let b = |i: usize| k.get(i).copied().unwrap_or(0);
    if !k.starts_with(b"\x06\x0e\x2b\x34") {
        return (Kind::Other, "Non-SMPTE KLV".to_owned());
    }
    if k.starts_with(PARTITION_PREFIX) {
        let kind = match b(13) {
            0x02 => "Header",
            0x03 => "Body",
            0x04 => "Footer",
            0x05 => return (Kind::Primer, "Primer pack".to_owned()),
            0x10 => return (Kind::Index, "Index table segment".to_owned()),
            0x11 => return (Kind::RandomIndex, "Random index pack".to_owned()),
            _ => "Unknown",
        };
        let status = match b(14) {
            0x01 => "open, incomplete",
            0x02 => "closed, incomplete",
            0x03 => "open, complete",
            0x04 => "closed, complete",
            _ => "?",
        };
        return (Kind::Partition, format!("{kind} partition pack ({status})"));
    }
    if b(4) == 0x02 && b(5) == 0x53 && b(8) == 0x0d && b(9) == 0x01 && b(10) == 0x02 && b(13) == 0x10 {
        return (Kind::Index, "Index table segment".to_owned());
    }
    if b(4) == 0x01 && b(8) == 0x03 && b(9) == 0x01 && b(10) == 0x02 && b(11) == 0x10 {
        return (Kind::Fill, "Fill item".to_owned());
    }
    if b(4) == 0x02 && b(5) == 0x53 && b(8) == 0x0d && b(9) == 0x01 && b(10) == 0x01 {
        let name = set_name(b(13), b(14));
        return (Kind::Set, name.to_owned());
    }
    if b(4) == 0x01 && b(5) == 0x02 && b(8) == 0x0d && b(9) == 0x01 && b(10) == 0x03 && b(11) == 0x01 {
        let item = match b(12) {
            0x04 => "CP system item",
            0x05 => "CP picture element",
            0x06 => "CP sound element",
            0x07 => "CP data element",
            0x14 => "GC system item",
            0x15 => "GC picture element",
            0x16 => "GC sound element",
            0x17 => "GC data element",
            0x18 => "GC compound element",
            _ => "Essence element",
        };
        return (Kind::Essence, format!("{item} (track {:02x}{:02x}{:02x}{:02x})", b(12), b(13), b(14), b(15)));
    }
    if b(8) == 0x0d && b(9) == 0x01 && b(10) == 0x03 && b(11) == 0x01 && b(12) == 0x04 {
        return (Kind::Other, "System metadata".to_owned());
    }
    (Kind::Other, "KLV".to_owned())
}

fn set_name(b13: u8, b14: u8) -> &'static str {
    if b13 != 0x01 {
        return "Metadata set";
    }
    match b14 {
        0x0f => "Sequence",
        0x11 => "Source Clip",
        0x14 => "Timecode Component",
        0x18 => "Content Storage",
        0x23 => "Essence Container Data",
        0x25 => "File Descriptor",
        0x27 => "Generic Picture Essence Descriptor",
        0x28 => "CDCI Essence Descriptor",
        0x29 => "RGBA Essence Descriptor",
        0x2f => "Preface",
        0x30 => "Identification",
        0x32 => "Network Locator",
        0x33 => "Text Locator",
        0x36 => "Material Package",
        0x37 => "Source Package",
        0x39 => "Event Track",
        0x3a => "Static Track",
        0x3b => "Timeline Track",
        0x41 => "DM Segment",
        0x42 => "Generic Sound Essence Descriptor",
        0x43 => "Generic Data Essence Descriptor",
        0x44 => "Multiple Descriptor",
        0x47 => "AES3 Audio Descriptor",
        0x48 => "Wave Audio Descriptor",
        0x51 => "MPEG-2 Video Descriptor",
        0x5a => "JPEG 2000 Picture Sub-Descriptor",
        0x5b => "VBI Data Descriptor",
        0x5c => "ANC Data Descriptor",
        _ => "Metadata set",
    }
}

/// Operational pattern name from its UL.
fn operational_pattern(ul: &[u8]) -> Option<String> {
    if !ul.starts_with(b"\x06\x0e\x2b\x34\x04\x01\x01") || ul.get(8..11) != Some(b"\x0d\x01\x02") {
        return None;
    }
    let item = *ul.get(12)?;
    let package = *ul.get(13)?;
    if ul.get(11) == Some(&0x01) && (1..=3).contains(&item) && (1..=3).contains(&package) {
        return Some(format!("OP{item}{}", char::from(b'a'.saturating_add(package.saturating_sub(1)))));
    }
    (ul.get(11) == Some(&0x10)).then(|| "OP-Atom".to_owned())
}

/// A coarse name for a picture or sound essence coding UL.
fn coding_name(ul: &[u8]) -> Option<&'static str> {
    let b = |i: usize| ul.get(i).copied().unwrap_or(0);
    if !ul.starts_with(b"\x06\x0e\x2b\x34\x04\x01\x01") || b(8) != 0x04 {
        return None;
    }
    Some(match (b(9), b(10), b(11), b(12), b(13)) {
        (0x01, 0x02, 0x02, 0x01, 0x20..=0x2f) => "MPEG-4 Visual",
        (0x01, 0x02, 0x02, 0x01, 0x30..=0x3f) => "H.264",
        (0x01, 0x02, 0x02, 0x01, _) => "MPEG-2 video",
        (0x01, 0x02, 0x02, 0x03, 0x01) => "JPEG 2000",
        (0x01, 0x02, 0x02, 0x02, _) => "DV",
        (0x01, 0x02, 0x02, 0x71, _) => "VC-3",
        (0x01, 0x02, 0x01, _, _) => "uncompressed picture",
        (0x02, 0x02, 0x01, _, _) => "PCM",
        (0x02, 0x02, 0x02, 0x03, 0x01) => "AC-3",
        (0x02, 0x02, 0x02, 0x03, 0x02) => "MPEG audio",
        (0x02, 0x02, 0x02, 0x03, 0x03) => "AAC",
        _ => return None,
    })
}

/// A BER length: value and the number of bytes it occupies.
fn ber(d: &[u8]) -> Option<(u64, usize)> {
    let first = *d.first()?;
    if first < 0x80 {
        return Some((first.into(), 1));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 8 {
        return None;
    }
    let bytes = d.get(1..n.checked_add(1)?)?;
    Some((bytes.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b)), n.checked_add(1)?))
}

fn ul_text(d: &[u8]) -> String {
    d.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.concat())
        .collect::<Vec<_>>()
        .join(".")
}

#[derive(Clone, Copy, Debug)]
struct Klv {
    span: Span,
    header_len: u64,
    kind: Kind,
    /// The primer pack of the current partition, for dynamic local tags.
    primer: Option<Span>,
}

impl Klv {
    fn value(&self) -> Span {
        self.span.tail(self.header_len)
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut primer = None;
    cx.annotate(file_summary(&cx, file).await?);
    while pos < file.len {
        let d = cx.read_avail(file.sub(pos, 25)).await?;
        let Some((len, ll)) = d.get(16..).and_then(ber) else {
            cx.emit(Node::new("Trailing bytes").span(file.tail(pos)));
            break;
        };
        let key = d.get(..16).unwrap_or_default();
        let (kind, name) = classify(key);
        let header_len = 16u64.saturating_add(to_u64(ll));
        let total = header_len.saturating_add(len);
        let span = file.sub(pos, total);
        match kind {
            Kind::Primer => primer = Some(span.tail(header_len)),
            Kind::Partition => primer = None,
            _ => {}
        }
        let klv = Klv {
            span,
            header_len,
            kind,
            primer,
        };
        let mut node = Node::new(name).span(span);
        if let Some(s) = describe(&cx, &klv).await {
            node = node.summary(s);
        }
        if span.len < total {
            node = node.diag(Diagnostic::truncated(Span::new(span.source, span.offset, total), span.len));
        }
        cx.push(node.lazy(expand_klv, klv)).await;
        pos = pos.saturating_add(total);
    }
    Ok(())
}

/// Reads the header partition's metadata sets for the file summary.
async fn file_summary(cx: &Cx, file: Span) -> Result<String> {
    let mut summary = Summary::default();
    let mut pos = 0u64;
    let mut end = file.len.min(0x40_0000);
    for _ in 0..4096 {
        if pos >= end {
            break;
        }
        let d = cx.read_avail(file.sub(pos, 25)).await?;
        let Some((len, ll)) = d.get(16..).and_then(ber) else {
            break;
        };
        let key = d.get(..16).unwrap_or_default();
        let (kind, _) = classify(key);
        let header_len = 16u64.saturating_add(to_u64(ll));
        let value = file.sub(pos.saturating_add(header_len), len);
        match kind {
            Kind::Partition if pos == 0 => {
                let v = vidutil::read_small(cx, value, 0x400).await?;
                summary.observe(kind, key, &v);
                // The header metadata follows the partition pack.
                let header_bytes = u64_be(&v, 32).unwrap_or(0);
                end = end.min(
                    pos.saturating_add(header_len)
                        .saturating_add(len)
                        .saturating_add(header_bytes),
                );
            }
            Kind::Partition | Kind::Essence => break,
            Kind::Set => {
                let v = vidutil::read_small(cx, value, 0x4000).await?;
                summary.observe(kind, key, &v);
            }
            _ => {}
        }
        pos = pos.saturating_add(header_len).saturating_add(len);
    }
    Ok(summary.describe())
}

async fn describe(cx: &Cx, klv: &Klv) -> Option<String> {
    let value = klv.value();
    match klv.kind {
        Kind::Fill | Kind::Essence | Kind::Other => Some(format!("{} bytes", value.len)),
        Kind::Partition => {
            let d = cx.read_avail(value.sub(0, 0x58)).await.ok()?;
            let op = d.get(64..80).and_then(operational_pattern);
            Some(format!(
                "at {:#x}{}",
                u64_be(&d, 8)?,
                op.map(|o| format!(", {o}")).unwrap_or_default()
            ))
        }
        Kind::Set => {
            let d = vidutil::read_small(cx, value, 0x2000).await.ok()?;
            set_summary(&d)
        }
        Kind::Primer => {
            let d = cx.read_avail(value.sub(0, 4)).await.ok()?;
            Some(format!("{} local tags", u32_be(&d, 0)?))
        }
        _ => None,
    }
}

/// Local set items: (tag, value).
fn local_items(d: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let tag = u16_be(d, at)?;
        let len = usize::from(u16_be(d, at.checked_add(2)?)?);
        let start = at.checked_add(4)?;
        let value = d.get(start..start.checked_add(len)?)?;
        at = start.checked_add(len)?;
        Some((tag, value))
    })
}

fn utf16be(d: &[u8]) -> String {
    crate::text::utf16(d, BE).trim_end_matches('\0').to_owned()
}

fn rational(d: &[u8]) -> Option<(i32, i32)> {
    Some((crate::bytes::i32_be(d, 0)?, crate::bytes::i32_be(d, 4)?))
}

fn set_summary(d: &[u8]) -> Option<String> {
    let mut parts = Vec::new();
    for (tag, v) in local_items(d) {
        match tag {
            0x3c02 | 0x4402 => parts.push(format!("\"{}\"", utf16be(v))),
            0x4801 => parts.push(format!("track {}", u32_be(v, 0)?)),
            0x3203 => parts.push(format!("width {}", u32_be(v, 0)?)),
            0x3202 => parts.push(format!("height {}", u32_be(v, 0)?)),
            0x3d03 => {
                let (n, den) = rational(v)?;
                if den != 0 {
                    parts.push(format!("{} Hz", vidutil::num(f64::from(n) / f64::from(den))));
                }
            }
            0x3d07 => parts.push(format!("{} ch", u32_be(v, 0)?)),
            0x3201 | 0x3d06 => {
                if let Some(c) = coding_name(v) {
                    parts.push(c.to_owned());
                }
            }
            _ => {}
        }
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

#[derive(Default)]
struct Summary {
    op: Option<String>,
    picture: Option<String>,
    sound: Option<String>,
    duration: Option<String>,
    product: Option<String>,
}

impl Summary {
    fn observe(&mut self, kind: Kind, key: &[u8], d: &[u8]) {
        if kind == Kind::Partition {
            if self.op.is_none() {
                self.op = d.get(64..80).and_then(operational_pattern);
            }
            return;
        }
        let set = key.get(14).copied().unwrap_or(0);
        let mut width = None;
        let mut height = None;
        let mut coding = None;
        let mut rate = None;
        let mut sample_rate = None;
        let mut channels = None;
        let mut container_duration = None;
        for (tag, v) in local_items(d) {
            match tag {
                0x3203 => width = u32_be(v, 0),
                0x3202 => height = u32_be(v, 0),
                0x3201 | 0x3d06 => coding = coding_name(v),
                0x3001 => rate = rational(v),
                0x3d03 => sample_rate = rational(v),
                0x3d07 => channels = u32_be(v, 0),
                0x3002 => container_duration = u64_be(v, 0),
                0x3c02 if set == 0x30 => self.product = Some(utf16be(v)),
                _ => {}
            }
        }
        if let (Some(w), Some(h)) = (width, height) {
            self.picture = Some(format!("{w}×{h} {}", coding.unwrap_or("video")));
            if let (Some((n, den)), Some(dur)) = (rate, container_duration)
                && n > 0
            {
                let seconds = dur as f64 * f64::from(den) / f64::from(n);
                self.duration = Some(vidutil::seconds_f64(seconds));
            }
        } else if let Some((n, den)) = sample_rate
            && den != 0
            && self.sound.is_none()
        {
            self.sound = Some(format!(
                "{} {} Hz{}",
                coding.unwrap_or("audio"),
                vidutil::num(f64::from(n) / f64::from(den)),
                channels.map(|c| format!(" {c} ch")).unwrap_or_default()
            ));
        }
    }

    fn describe(&self) -> String {
        let mut parts = vec![match &self.op {
            Some(op) => format!("MXF {op}"),
            None => "MXF".to_owned(),
        }];
        let streams: Vec<&String> = [&self.picture, &self.sound].into_iter().flatten().collect();
        if !streams.is_empty() {
            parts.push(streams.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" + "));
        }
        if let Some(d) = &self.duration {
            parts.push(d.clone());
        }
        if let Some(p) = &self.product {
            parts.push(format!("written by {p}"));
        }
        parts.join(", ")
    }
}

record! {
    pub struct PartitionPack {
        major: u16 "Major version",
        minor: u16 "Minor version",
        kag: u32 "KAG size",
        this: u64 "This partition" .hex(),
        previous: u64 "Previous partition" .hex(),
        footer: u64 "Footer partition" .hex(),
        header_bytes: u64 "Header byte count",
        index_bytes: u64 "Index byte count",
        index_sid: u32 "Index SID",
        body_offset: u64 "Body offset",
        body_sid: u32 "Body SID",
    }
}

async fn expand_klv(cx: Cx, klv: Klv) -> Result<()> {
    let key = cx.read_avail(klv.span.sub(0, 16)).await?;
    cx.emit(text("Key", klv.span.sub(0, 16), ul_text(&key)));
    cx.emit(uint(
        "Length",
        klv.span.sub(16, klv.header_len.saturating_sub(16)),
        klv.value().len,
        64,
    ));
    let value = klv.value();
    match klv.kind {
        Kind::Partition => {
            let block = cx.block(value.sub(0, 0x10000)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            PartitionPack::read(&mut f)?;
            let op = f.bytes("Operational pattern", 16);
            let span = op.span();
            let op = op.get()?;
            let mut node = text("Operational pattern", span, ul_text(&op));
            if let Some(name) = operational_pattern(&op) {
                node = node.summary(name);
            }
            f.node(node);
            batch(&mut f, "Essence container")?;
        }
        Kind::Primer => {
            let block = cx.block(value.sub(0, 0x10000)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            let n = f.u32("Item count").emit()?;
            f.u32("Item length").emit()?;
            for _ in 0..n {
                if f.remaining() < 18 {
                    break;
                }
                let tag = f.u16("Local tag").get()?;
                let ul = f.bytes("UL", 16);
                let span = ul.span();
                let ul = ul.get()?;
                f.node(
                    text(format!("Tag {tag:#06x}"), Span::new(span.source, span.offset.saturating_sub(2), 18), ul_text(&ul))
                        .summary(local_tag_name(tag).unwrap_or("")),
                );
            }
        }
        Kind::Set => local_set(&cx, value, klv.primer).await?,
        Kind::RandomIndex => {
            let block = cx.block(value.sub(0, 0x10000)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            while f.remaining() >= 16 {
                f.u32("Body SID").emit()?;
                f.u64("Partition offset").hex().emit()?;
            }
            if f.remaining() >= 4 {
                f.u32("Overall length").emit()?;
            }
        }
        Kind::Index => local_set(&cx, value, klv.primer).await?,
        _ => {
            if !value.is_empty() {
                cx.emit(Node::new("Value").span(value).summary(format!("{} bytes", value.len)));
            }
        }
    }
    Ok(())
}

/// A batch: count, item length, items (ULs).
fn batch(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    if f.remaining() < 8 {
        return Ok(());
    }
    let n = f.u32("Batch count").emit()?;
    let size = f.u32("Item length").emit()?;
    for _ in 0..n {
        if f.remaining() < u64::from(size) || size == 0 {
            break;
        }
        let item = f.bytes(name, size.into());
        let span = item.span();
        let item = item.get()?;
        f.node(text(name, span, ul_text(&item)));
    }
    Ok(())
}

/// Static local tag names (SMPTE 377M annex B and common descriptors).
fn local_tag_name(tag: u16) -> Option<&'static str> {
    Some(match tag {
        0x3c0a => "Instance UID",
        0x0102 => "Generation UID",
        0x3b02 => "Last modified date",
        0x3b05 => "Version",
        0x3b07 => "Object model version",
        0x3b03 => "Content storage",
        0x3b08 => "Primary package",
        0x3b06 => "Identifications",
        0x3b09 => "Operational pattern",
        0x3b0a => "Essence containers",
        0x3b0b => "DM schemes",
        0x3c09 => "This generation UID",
        0x3c01 => "Company name",
        0x3c02 => "Product name",
        0x3c03 => "Product version",
        0x3c04 => "Version string",
        0x3c05 => "Product UID",
        0x3c06 => "Modification date",
        0x3c07 => "Toolkit version",
        0x3c08 => "Platform",
        0x1901 => "Packages",
        0x1902 => "Essence container data",
        0x2701 => "Linked package UID",
        0x3f06 => "Index SID",
        0x3f07 => "Body SID",
        0x4401 => "Package UID",
        0x4402 => "Name",
        0x4405 => "Package creation date",
        0x4404 => "Package modified date",
        0x4403 => "Tracks",
        0x4701 => "Descriptor",
        0x4801 => "Track ID",
        0x4804 => "Track number",
        0x4802 => "Track name",
        0x4803 => "Sequence",
        0x4b01 => "Edit rate",
        0x4b02 => "Origin",
        0x0201 => "Data definition",
        0x0202 => "Duration",
        0x1001 => "Structural components",
        0x1201 => "Start position",
        0x1101 => "Source package ID",
        0x1102 => "Source track ID",
        0x1501 => "Start timecode",
        0x1502 => "Rounded timecode base",
        0x1503 => "Drop frame",
        0x2f01 => "Locators",
        0x3001 => "Sample rate",
        0x3002 => "Container duration",
        0x3004 => "Essence container",
        0x3005 => "Codec",
        0x3006 => "Linked track ID",
        0x3f01 => "Sub-descriptors",
        0x3201 => "Picture essence coding",
        0x3202 => "Stored height",
        0x3203 => "Stored width",
        0x3204 => "Sampled height",
        0x3205 => "Sampled width",
        0x3206 => "Sampled X offset",
        0x3207 => "Sampled Y offset",
        0x3208 => "Display height",
        0x3209 => "Display width",
        0x320c => "Frame layout",
        0x320d => "Video line map",
        0x320e => "Aspect ratio",
        0x3210 => "Transfer characteristic",
        0x3211 => "Image alignment offset",
        0x3301 => "Component depth",
        0x3302 => "Horizontal subsampling",
        0x3303 => "Color siting",
        0x3304 => "Black ref level",
        0x3305 => "White ref level",
        0x3306 => "Color range",
        0x3308 => "Vertical subsampling",
        0x3d01 => "Quantization bits",
        0x3d02 => "Locked",
        0x3d03 => "Audio sampling rate",
        0x3d06 => "Sound essence compression",
        0x3d07 => "Channel count",
        0x3d09 => "Average bytes per second",
        0x3d0a => "Block align",
        0x3d0d => "Emphasis",
        0x3f05 => "Edit unit byte count",
        0x3f08 => "Slice count",
        0x3f09 => "Delta entry array",
        0x3f0a => "Index entry array",
        0x3f0b => "Index edit rate",
        0x3f0c => "Index start position",
        0x3f0d => "Index duration",
        0x3f0e => "PosTable count",
        _ => return None,
    })
}

async fn local_set(cx: &Cx, value: Span, primer: Option<Span>) -> Result<()> {
    let d = vidutil::read_small(cx, value, 0x100000).await?;
    let primer = match primer {
        Some(p) => vidutil::read_small(cx, p, 0x100000).await?,
        None => Vec::new(),
    };
    let mut at = 0usize;
    for (tag, v) in local_items(&d) {
        let total = v.len().saturating_add(4);
        let span = vidutil::at(value, at, total);
        let vspan = span.tail(4);
        at = at.saturating_add(total);
        let name = local_tag_name(tag).map_or_else(
            || match dynamic_ul(&primer, tag) {
                Some(ul) => format!("Tag {tag:#06x} ({})", ul_text(&ul)),
                None => format!("Tag {tag:#06x}"),
            },
            str::to_owned,
        );
        cx.emit(item_node(name, tag, span, vspan, v));
    }
    let rest = value.tail(to_u64(at));
    if !rest.is_empty() {
        cx.emit(Node::new("Unparsed data").span(rest));
    }
    Ok(())
}

/// The UL a dynamic local tag stands for, from the primer pack.
fn dynamic_ul(primer: &[u8], tag: u16) -> Option<Vec<u8>> {
    let n = u32_be(primer, 0)?;
    let mut at = 8usize;
    for _ in 0..n.min(65536) {
        if u16_be(primer, at)? == tag {
            return primer.get(at.saturating_add(2)..at.saturating_add(18)).map(<[u8]>::to_vec);
        }
        at = at.saturating_add(18);
    }
    None
}

fn item_node(name: String, tag: u16, span: Span, vspan: Span, v: &[u8]) -> Node {
    let node = Node::new(name).span(span);
    match tag {
        0x3c01 | 0x3c02 | 0x3c04 | 0x3c08 | 0x4402 | 0x4802 => node.value(Value::Text(utf16be(v))),
        0x3b02 | 0x3c06 | 0x4404 | 0x4405 => node.value(Value::Text(timestamp(v))),
        0x4b01 | 0x3001 | 0x3d03 | 0x320e | 0x3f0b => match rational(v) {
            Some((n, d)) => node.value(Value::Text(format!("{n}/{d}"))).summary(if d != 0 {
                vidutil::num(f64::from(n) / f64::from(d))
            } else {
                "∞".to_owned()
            }),
            None => node.value(Value::Bytes(v.to_vec())),
        },
        0x0202 | 0x3002 | 0x4b02 | 0x1201 | 0x3f0c | 0x3f0d => {
            node.value(Value::Int {
                value: crate::bytes::array::<8>(v, 0).map_or(0, i64::from_be_bytes),
                bits: 64,
            })
        }
        0x3203 | 0x3202 | 0x3204 | 0x3205 | 0x3208 | 0x3209 | 0x3301 | 0x3302 | 0x3308
        | 0x3d01 | 0x3d07 | 0x3d09 | 0x4801 | 0x3006 | 0x1102 | 0x3f06 | 0x3f07 | 0x3f05 | 0x3206
        | 0x3207 | 0x3304 | 0x3305 | 0x3306 | 0x320c | 0x3303 | 0x3d0a | 0x1502 | 0x1503 | 0x1501 => {
            uint_value(node, v)
        }
        0x4804 => match u32_be(v, 0) {
            Some(n) => node.value(Value::UInt {
                value: n.into(),
                bits: 32,
                radix: crate::value::Radix::Hex,
            }),
            None => node.value(Value::Bytes(v.to_vec())),
        },
        0x3201 | 0x3d06 | 0x3b09 | 0x3004 | 0x0201 => {
            let mut n = node.value(Value::Text(ul_text(v)));
            if let Some(c) = coding_name(v) {
                n = n.summary(c);
            } else if let Some(op) = operational_pattern(v) {
                n = n.summary(op);
            }
            n
        }
        0x3c0a | 0x4401 | 0x0102 | 0x3c09 | 0x3c05 | 0x2701 | 0x1101 | 0x3b03 | 0x3b08 | 0x4701
        | 0x4803 => node.value(Value::Text(ul_text(v))),
        0x3b06 | 0x1901 | 0x1902 | 0x4403 | 0x1001 | 0x3f01 | 0x3b0a | 0x3b0b | 0x2f01 => {
            let count = u32_be(v, 0).unwrap_or(0);
            node.summary(format!("{count} items")).desc("Batch or array of references")
        }
        _ if v.len() <= 16 => node.value(Value::Bytes(v.to_vec())),
        _ => node.summary(format!("{} bytes", vspan.len)),
    }
}

fn uint_value(node: Node, v: &[u8]) -> Node {
    let value = match v.len() {
        1..=8 => v.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b)),
        _ => return node.value(Value::Bytes(v.to_vec())),
    };
    node.value(Value::UInt {
        value,
        bits: u8::try_from(v.len().saturating_mul(8)).unwrap_or(64),
        radix: crate::value::Radix::Dec,
    })
}

/// An MXF timestamp: year, month, day, hour, minute, second, 1/250 s.
fn timestamp(v: &[u8]) -> String {
    let (Some(y), Some(rest)) = (u16_be(v, 0), v.get(2..7)) else {
        return String::new();
    };
    let g = |i: usize| rest.get(i).copied().unwrap_or(0);
    format!(
        "{y:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        g(0),
        g(1),
        g(2),
        g(3),
        g(4)
    )
}
