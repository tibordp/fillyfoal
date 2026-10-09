//! MPEG-4 Systems descriptors (ISO/IEC 14496-1 7.2.6): the ES_Descriptor
//! of an ISOBMFF `esds` box or a CAF `kuki` chunk, the object descriptors
//! of `iods`, and the DecoderConfigDescriptor and DecoderSpecificInfo (an
//! AudioSpecificConfig for MPEG-4 audio) they nest.

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

use super::{bitrate, enumerated, flag_node, lookup_or, nal, uint};

pub const OBJECT_TYPES: EnumTable = &[
    (0x01, "Systems (14496-1)"),
    (0x02, "Systems (14496-1) v2"),
    (0x20, "MPEG-4 Visual"),
    (0x21, "H.264"),
    (0x22, "H.264 parameter sets"),
    (0x23, "HEVC"),
    (0x40, "MPEG-4 Audio"),
    (0x60, "MPEG-2 Visual Simple"),
    (0x61, "MPEG-2 Visual Main"),
    (0x62, "MPEG-2 Visual SNR"),
    (0x63, "MPEG-2 Visual Spatial"),
    (0x64, "MPEG-2 Visual High"),
    (0x65, "MPEG-2 Visual 4:2:2"),
    (0x66, "MPEG-2 AAC Main"),
    (0x67, "MPEG-2 AAC LC"),
    (0x68, "MPEG-2 AAC SSR"),
    (0x69, "MPEG-2 Audio (MP3)"),
    (0x6a, "MPEG-1 Visual"),
    (0x6b, "MPEG-1 Audio (MP3)"),
    (0x6c, "JPEG"),
    (0x6d, "PNG"),
    (0x6e, "JPEG 2000"),
    (0xa3, "VC-1"),
    (0xa4, "Dirac"),
    (0xa5, "AC-3"),
    (0xa6, "E-AC-3"),
    (0xa9, "DTS"),
    (0xaa, "DTS-HD High Resolution"),
    (0xab, "DTS-HD Master Audio"),
    (0xac, "DTS Express"),
    (0xad, "Opus"),
    (0xb1, "VP9"),
    (0xdd, "Vorbis"),
    (0xe1, "QCELP"),
];

pub const STREAM_TYPES: EnumTable = &[
    (1, "ObjectDescriptor"),
    (2, "ClockReference"),
    (3, "SceneDescription"),
    (4, "Visual"),
    (5, "Audio"),
    (6, "MPEG-7"),
    (7, "IPMP"),
    (8, "OCI"),
    (9, "MPEG-J"),
    (10, "Interaction"),
    (11, "IPMP tool"),
    (32, "Text (3GPP)"),
];

pub const DESCRIPTOR_TAGS: EnumTable = &[
    (0x01, "ObjectDescriptor"),
    (0x02, "InitialObjectDescriptor"),
    (0x03, "ES_Descriptor"),
    (0x04, "DecoderConfigDescriptor"),
    (0x05, "DecoderSpecificInfo"),
    (0x06, "SLConfigDescriptor"),
    (0x0e, "ES_ID_Inc"),
    (0x0f, "ES_ID_Ref"),
    (0x10, "MP4_IOD"),
    (0x11, "MP4_OD"),
];

pub const SL_PREDEFINED: EnumTable = &[
    (0, "custom"),
    (1, "null SL packet header"),
    (2, "MP4 (reserved for ISO files)"),
];

/// The codec an objectTypeIndication names.
pub fn object_type_codec(oti: u8) -> Option<&'static str> {
    Some(match oti {
        0x20 => "MPEG-4 Visual",
        0x21 => "H.264",
        0x23 => "HEVC",
        0x40 | 0x66..=0x68 => "AAC",
        0x60..=0x65 => "MPEG-2 video",
        0x69 | 0x6b => "MP3",
        0x6a => "MPEG-1 video",
        0x6c => "JPEG",
        0x6d => "PNG",
        0x6e => "JPEG 2000",
        0xa3 => "VC-1",
        0xa4 => "Dirac",
        0xa5 => "AC-3",
        0xa6 => "E-AC-3",
        0xa9..=0xac => "DTS",
        0xad => "Opus",
        0xb1 => "VP9",
        0xdd => "Vorbis",
        0xe1 => "QCELP",
        _ => return None,
    })
}

/// Whether an objectTypeIndication is MPEG-4 or MPEG-2 AAC (whose
/// DecoderSpecificInfo is an AudioSpecificConfig).
pub fn is_aac(oti: u8) -> bool {
    matches!(oti, 0x40 | 0x66 | 0x67 | 0x68)
}

/// A descriptor header: (tag, body length, header length). The size is
/// "expandable": 7 bits per byte, at most four bytes.
pub fn header(d: &[u8]) -> Option<(u8, u64, u64)> {
    let tag = d.first().copied()?;
    let mut size = 0u64;
    for i in 1..5usize {
        let b = d.get(i).copied()?;
        size = (size << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((tag, size, to_u64(i.saturating_add(1))));
        }
    }
    None
}

#[derive(Clone, Copy, Debug)]
struct Descriptor {
    input: Input,
    span: Span,
    header_len: u64,
    tag: u8,
    /// objectTypeIndication of the enclosing DecoderConfigDescriptor.
    object_type: u8,
}

/// Lists the descriptors in `span` (paged); `object_type` is the
/// objectTypeIndication in effect (0 at the top).
pub async fn descriptors(cx: &Cx, input: Input, span: Span, object_type: u8) -> Result<()> {
    let mut pos = 0u64;
    let mut count = 0u32;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 5)).await?;
        let Some((tag, size, header_len)) = header(&head) else {
            cx.emit(Node::new("Data").span(span.tail(pos)));
            break;
        };
        let total = header_len.saturating_add(size);
        let d = Descriptor {
            input,
            span: span.sub(pos, total),
            header_len,
            tag,
            object_type,
        };
        let name = crate::value::lookup(DESCRIPTOR_TAGS, tag.into())
            .map_or_else(|| format!("Descriptor {tag:#04x}"), str::to_owned);
        let mut node = Node::new(name).span(d.span);
        if let Some(s) = descriptor_summary(cx, &d).await {
            node = node.summary(s);
        }
        cx.push(node.lazy(crate::expander!(self::descriptor: Descriptor), d))
            .await;
        pos = pos.saturating_add(total.max(1));
        count = count.saturating_add(1);
        if count > 4096 {
            break;
        }
    }
    Ok(())
}

async fn descriptor_summary(cx: &Cx, d: &Descriptor) -> Option<String> {
    let body = d.span.tail(d.header_len);
    match d.tag {
        0x03 => {
            // The summary of what the stream is, from the nested
            // DecoderConfigDescriptor.
            let data = cx.read_avail(d.span.sub(0, 256)).await.ok()?;
            let es = u16_be(&data, usize::try_from(d.header_len).ok()?)?;
            Some(match esds_summary(&data) {
                Some(s) => format!("ES_ID {es}: {s}"),
                None => format!("ES_ID {es}"),
            })
        }
        0x04 => {
            let data = cx.read_avail(body.sub(0, 64)).await.ok()?;
            let oti = data.first().copied()?;
            let mut s = lookup_or(OBJECT_TYPES, oti.into());
            if let Some(avg) = u32_be(&data, 9).filter(|&v| v > 0) {
                s = format!("{s}, {}", bitrate(avg.into()));
            }
            Some(s)
        }
        0x05 if is_aac(d.object_type) => {
            let data = cx.read_avail(body.sub(0, 256)).await.ok()?;
            super::asc_summary(&data)
        }
        0x06 => {
            let data = cx.read_avail(body.sub(0, 1)).await.ok()?;
            Some(lookup_or(SL_PREDEFINED, (*data.first()?).into()))
        }
        _ => None,
    }
}

async fn descriptor(cx: Cx, d: Descriptor) -> Result<()> {
    let head = d.span.sub(0, d.header_len);
    cx.emit(enumerated(
        "Tag",
        head.sub(0, 1),
        d.tag.into(),
        8,
        DESCRIPTOR_TAGS,
    ));
    cx.emit(
        uint(
            "Size",
            head.tail(1),
            d.span.len.saturating_sub(d.header_len),
            32,
        )
        .desc("Expandable: 7 bits per byte, high bit set on all but the last"),
    );
    let body = d.span.tail(d.header_len);
    let block = cx.block(body.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(&cx, &block, Endian::Big);
    match d.tag {
        0x03 => {
            f.u16("ES_ID").emit()?;
            let span = f.peek_span(1);
            let flags = f.u8("Flags").get()?;
            f.node(flag_node("Stream dependence", span, flags & 0x80 != 0));
            f.node(flag_node("URL", span, flags & 0x40 != 0));
            f.node(flag_node("OCR stream", span, flags & 0x20 != 0));
            f.node(uint("Stream priority", span, (flags & 0x1f).into(), 5));
            if flags & 0x80 != 0 {
                f.u16("Depends on ES_ID").emit()?;
            }
            if flags & 0x40 != 0 {
                let len = f.u8("URL length").emit()?;
                f.ascii("URL string", len.into()).emit()?;
            }
            if flags & 0x20 != 0 {
                f.u16("OCR ES_ID").emit()?;
            }
            let at = f.pos();
            descriptors(&cx, d.input, body.tail(at), d.object_type).await?;
        }
        0x04 => {
            let oti = f
                .u8("Object type indication")
                .enumeration(OBJECT_TYPES)
                .emit()?;
            let span = f.peek_span(1);
            let v = f.u8("Stream type").get()?;
            f.node(enumerated(
                "Stream type",
                span,
                (v >> 2).into(),
                6,
                STREAM_TYPES,
            ));
            f.node(flag_node("Upstream", span, v & 2 != 0));
            f.node(uint("Reserved", span, (v & 1).into(), 1));
            crate::formats::util::sound::u24(&mut f, "Buffer size", Endian::Big)
                .with(|&v, n| n.summary(format!("{v} bytes")))
                .emit()?;
            f.u32("Max bitrate")
                .with(|&v, n| n.summary(bitrate(v.into())))
                .emit()?;
            f.u32("Average bitrate")
                .with(|&v, n| {
                    n.summary(if v == 0 {
                        "variable".to_owned()
                    } else {
                        bitrate(v.into())
                    })
                })
                .emit()?;
            let at = f.pos();
            descriptors(&cx, d.input, body.tail(at), oti).await?;
        }
        0x05 => {
            if is_aac(d.object_type) {
                let data = block.data.get(..256).unwrap_or(block.data.as_slice());
                let span = body.sub(0, to_u64(data.len()));
                let (asc, nodes) = nal::asc(data, span, true);
                let mut node = nal::group("AudioSpecificConfig", body, nodes);
                if let Some(a) = asc {
                    node = node.summary(a.describe());
                }
                cx.emit(node);
            } else if matches!(
                d.object_type,
                0x20 | 0x60..=0x65 | 0x6a | 0x6c | 0x6d | 0x6e
            ) {
                cx.emit(embedded("Decoder specific info", d.input.nested(body)));
            } else {
                let len = f.remaining();
                f.bytes("Decoder specific info", len).emit()?;
            }
        }
        0x06 => {
            f.u8("Predefined").enumeration(SL_PREDEFINED).emit()?;
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("SL config", rest).emit()?;
            }
        }
        0x0e => {
            f.u32("Track ID").emit()?;
        }
        0x01 | 0x02 | 0x10 | 0x11 => {
            let span = f.peek_span(2);
            let v = f.u16("Object descriptor header").get()?;
            f.node(uint("Object descriptor ID", span, (v >> 6).into(), 10));
            f.node(flag_node("URL", span, v & 0x20 != 0));
            let initial = matches!(d.tag, 0x02 | 0x10);
            if initial {
                f.node(flag_node(
                    "Include inline profile level",
                    span,
                    v & 0x10 != 0,
                ));
                f.node(uint("Reserved", span, (v & 0xf).into(), 4));
            } else {
                f.node(uint("Reserved", span, (v & 0x1f).into(), 5));
            }
            if v & 0x20 != 0 {
                let len = f.u8("URL length").emit()?;
                f.ascii("URL string", len.into()).emit()?;
            } else if initial {
                for name in [
                    "OD profile level",
                    "Scene profile level",
                    "Audio profile level",
                    "Visual profile level",
                    "Graphics profile level",
                ] {
                    f.u8(name).hex().emit()?;
                }
            }
            let at = f.pos();
            descriptors(&cx, d.input, body.tail(at), d.object_type).await?;
        }
        _ => {
            if !body.is_empty() {
                cx.emit(Node::new("Data").span(body));
            }
        }
    }
    Ok(())
}

/// A codec description from an ES_Descriptor ("AAC-LC, 44100 Hz, stereo,
/// 128 kb/s").
pub fn esds_summary(d: &[u8]) -> Option<String> {
    let (oti, dsi, avg) = esds_info(d)?;
    let mut s = match dsi.filter(|_| is_aac(oti)).and_then(super::asc_summary) {
        Some(asc) => asc,
        None => lookup_or(OBJECT_TYPES, oti.into()),
    };
    if avg > 0 {
        s = format!("{s}, {}", bitrate(avg.into()));
    }
    Some(s)
}

/// (objectTypeIndication, DecoderSpecificInfo, average bitrate) from an
/// ES_Descriptor, walking ES_Descriptor → DecoderConfigDescriptor →
/// DecoderSpecificInfo.
pub fn esds_info(d: &[u8]) -> Option<(u8, Option<&[u8]>, u32)> {
    let mut at = 0usize;
    let mut oti = None;
    let mut avg = 0u32;
    for _ in 0..8 {
        let (tag, size, hl) = header(d.get(at..)?)?;
        let body = at.saturating_add(usize::try_from(hl).ok()?);
        match tag {
            0x03 => {
                let flags = d.get(body.saturating_add(2)).copied()?;
                let mut skip = 3usize;
                if flags & 0x80 != 0 {
                    skip = skip.saturating_add(2);
                }
                if flags & 0x40 != 0 {
                    let len = d.get(body.saturating_add(skip)).copied()?;
                    skip = skip.saturating_add(1).saturating_add(len.into());
                }
                if flags & 0x20 != 0 {
                    skip = skip.saturating_add(2);
                }
                at = body.saturating_add(skip);
            }
            0x04 => {
                oti = Some(d.get(body).copied()?);
                avg = u32_be(d, body.saturating_add(9)).unwrap_or(0);
                at = body.saturating_add(13);
            }
            0x05 => {
                let end = body.saturating_add(usize::try_from(size).ok()?);
                return Some((oti?, d.get(body..end.min(d.len())), avg));
            }
            _ => return oti.map(|o| (o, None, avg)),
        }
    }
    oti.map(|o| (o, None, avg))
}
