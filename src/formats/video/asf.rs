//! Advanced Systems Format (ASF): WMV, WMA and plain ASF files.
//!
//! The file is a sequence of objects `GUID, size (u64), body`. The header
//! object holds metadata objects (file and stream properties, content
//! descriptions, codec list, header extension); the data object holds
//! fixed-size packets, listed in pages.

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::vidutil;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Value, flag};

const LE: Endian = Endian::Little;

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
    Guid {
        data1,
        data2,
        data3,
        data4,
    }
}

const HEADER: Guid = guid(
    0x75b2_2630,
    0x668e,
    0x11cf,
    [0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c],
);
const DATA: Guid = guid(
    0x75b2_2636,
    0x668e,
    0x11cf,
    [0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c],
);
const FILE_PROPERTIES: Guid = guid(
    0x8cab_dca1,
    0xa947,
    0x11cf,
    [0x8e, 0xe4, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65],
);
const STREAM_PROPERTIES: Guid = guid(
    0xb7dc_0791,
    0xa9b7,
    0x11cf,
    [0x8e, 0xe6, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65],
);
const HEADER_EXTENSION: Guid = guid(
    0x5fbf_03b5,
    0xa92e,
    0x11cf,
    [0x8e, 0xe3, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65],
);
const CODEC_LIST: Guid = guid(
    0x86d1_5240,
    0x311d,
    0x11d0,
    [0xa3, 0xa4, 0x00, 0xa0, 0xc9, 0x03, 0x48, 0xf6],
);
const CONTENT_DESCRIPTION: Guid = guid(
    0x75b2_2633,
    0x668e,
    0x11cf,
    [0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c],
);
const EXTENDED_CONTENT: Guid = guid(
    0xd2d0_a440,
    0xe307,
    0x11d2,
    [0x97, 0xf0, 0x00, 0xa0, 0xc9, 0x5e, 0xa8, 0x50],
);
const STREAM_BITRATES: Guid = guid(
    0x7bf8_75ce,
    0x468d,
    0x11d1,
    [0x8d, 0x82, 0x00, 0x60, 0x97, 0xc9, 0xa2, 0xb2],
);
const METADATA: Guid = guid(
    0xc5f8_cbea,
    0x5baf,
    0x4877,
    [0x84, 0x67, 0xaa, 0x8c, 0x44, 0xfa, 0x4c, 0xca],
);
const METADATA_LIBRARY: Guid = guid(
    0x4423_1c94,
    0x9498,
    0x49d1,
    [0xa1, 0x41, 0x1d, 0x13, 0x4e, 0x45, 0x70, 0x54],
);
const LANGUAGE_LIST: Guid = guid(
    0x7c43_46a9,
    0xefe0,
    0x4bfc,
    [0xb2, 0x29, 0x39, 0x3e, 0xde, 0x41, 0x5c, 0x85],
);
const EXTENDED_STREAM: Guid = guid(
    0x14e6_a5cb,
    0xc672,
    0x4332,
    [0x83, 0x99, 0xa9, 0x69, 0x52, 0x06, 0x5b, 0x5a],
);
const SIMPLE_INDEX: Guid = guid(
    0x3300_0890,
    0xe5b1,
    0x11cf,
    [0x89, 0xf4, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xcb],
);

const AUDIO_MEDIA: Guid = guid(
    0xf869_9e40,
    0x5b4d,
    0x11cf,
    [0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b],
);
const VIDEO_MEDIA: Guid = guid(
    0xbc19_efc0,
    0x5b4d,
    0x11cf,
    [0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b],
);

const NAMES: &[(Guid, &str)] = &[
    (HEADER, "Header"),
    (DATA, "Data"),
    (SIMPLE_INDEX, "Simple Index"),
    (
        guid(
            0xd6e2_29d3,
            0x35da,
            0x11d1,
            [0x90, 0x34, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xbe],
        ),
        "Index",
    ),
    (
        guid(
            0xfeb1_03f8,
            0x12ad,
            0x4c64,
            [0x84, 0x0f, 0x2a, 0x1d, 0x2f, 0x7a, 0xd4, 0x8c],
        ),
        "Media Object Index",
    ),
    (
        guid(
            0x3cb7_3fd0,
            0x0c4a,
            0x4803,
            [0x95, 0x3d, 0xed, 0xf7, 0xb6, 0x22, 0x8f, 0x0c],
        ),
        "Timecode Index",
    ),
    (FILE_PROPERTIES, "File Properties"),
    (STREAM_PROPERTIES, "Stream Properties"),
    (HEADER_EXTENSION, "Header Extension"),
    (CODEC_LIST, "Codec List"),
    (
        guid(
            0x1efb_1a30,
            0x0b62,
            0x11d0,
            [0xa3, 0x9b, 0x00, 0xa0, 0xc9, 0x03, 0x48, 0xf6],
        ),
        "Script Command",
    ),
    (
        guid(
            0xf487_cd01,
            0xa951,
            0x11cf,
            [0x8e, 0xe6, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65],
        ),
        "Marker",
    ),
    (
        guid(
            0xd6e2_29dc,
            0x35da,
            0x11d1,
            [0x90, 0x34, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xbe],
        ),
        "Bitrate Mutual Exclusion",
    ),
    (
        guid(
            0x75b2_2635,
            0x668e,
            0x11cf,
            [0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c],
        ),
        "Error Correction",
    ),
    (CONTENT_DESCRIPTION, "Content Description"),
    (EXTENDED_CONTENT, "Extended Content Description"),
    (
        guid(
            0x2211_b3fa,
            0xbd23,
            0x11d2,
            [0xb4, 0xb7, 0x00, 0xa0, 0xc9, 0x55, 0xfc, 0x6e],
        ),
        "Content Branding",
    ),
    (STREAM_BITRATES, "Stream Bitrate Properties"),
    (
        guid(
            0x2211_b3fb,
            0xbd23,
            0x11d2,
            [0xb4, 0xb7, 0x00, 0xa0, 0xc9, 0x55, 0xfc, 0x6e],
        ),
        "Content Encryption",
    ),
    (
        guid(
            0x298a_e614,
            0x2622,
            0x4c17,
            [0xb9, 0x35, 0xda, 0xe0, 0x7e, 0xe9, 0x28, 0x9c],
        ),
        "Extended Content Encryption",
    ),
    (
        guid(
            0x2211_b3fc,
            0xbd23,
            0x11d2,
            [0xb4, 0xb7, 0x00, 0xa0, 0xc9, 0x55, 0xfc, 0x6e],
        ),
        "Digital Signature",
    ),
    (
        guid(
            0x1806_d474,
            0xcadf,
            0x4509,
            [0xa4, 0xba, 0x9a, 0xab, 0xcb, 0x96, 0xaa, 0xe8],
        ),
        "Padding",
    ),
    (EXTENDED_STREAM, "Extended Stream Properties"),
    (
        guid(
            0xa086_49cf,
            0x4775,
            0x4670,
            [0x8a, 0x16, 0x6e, 0x35, 0x35, 0x75, 0x66, 0xcd],
        ),
        "Advanced Mutual Exclusion",
    ),
    (
        guid(
            0xd146_5a40,
            0x5a79,
            0x4338,
            [0xb7, 0x1b, 0xe3, 0x6b, 0x8f, 0xd6, 0xc2, 0x49],
        ),
        "Group Mutual Exclusion",
    ),
    (
        guid(
            0xd4fe_d15b,
            0x88d3,
            0x454f,
            [0x81, 0xf0, 0xed, 0x5c, 0x45, 0x99, 0x9e, 0x24],
        ),
        "Stream Prioritization",
    ),
    (
        guid(
            0xa696_09e6,
            0x517b,
            0x11d2,
            [0xb6, 0xaf, 0x00, 0xc0, 0x4f, 0xd9, 0x08, 0xe9],
        ),
        "Bandwidth Sharing",
    ),
    (LANGUAGE_LIST, "Language List"),
    (METADATA, "Metadata"),
    (METADATA_LIBRARY, "Metadata Library"),
    (
        guid(
            0xd6e2_29df,
            0x35da,
            0x11d1,
            [0x90, 0x34, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xbe],
        ),
        "Index Parameters",
    ),
    (
        guid(
            0x6b20_3bad,
            0x3f11,
            0x48e4,
            [0xac, 0xa8, 0xd7, 0x61, 0x3d, 0xe2, 0xcf, 0xa7],
        ),
        "Media Object Index Parameters",
    ),
    (
        guid(
            0xf55e_496d,
            0x9797,
            0x4b5d,
            [0x8c, 0x8b, 0x60, 0x4d, 0xfe, 0x9b, 0xfb, 0x24],
        ),
        "Timecode Index Parameters",
    ),
    (
        guid(
            0x26f1_8b5d,
            0x4584,
            0x47ec,
            [0x9f, 0x5f, 0x0e, 0x65, 0x1f, 0x04, 0x52, 0xc9],
        ),
        "Compatibility",
    ),
    (
        guid(
            0x4305_8533,
            0x6981,
            0x49e6,
            [0x9b, 0x74, 0xad, 0x12, 0xcb, 0x86, 0xd5, 0x8c],
        ),
        "Advanced Content Encryption",
    ),
    (AUDIO_MEDIA, "Audio Media"),
    (VIDEO_MEDIA, "Video Media"),
    (
        guid(
            0x59da_cfc0,
            0x59e6,
            0x11d0,
            [0xa3, 0xac, 0x00, 0xa0, 0xc9, 0x03, 0x48, 0xf6],
        ),
        "Command Media",
    ),
    (
        guid(
            0xb61b_e100,
            0x5b4e,
            0x11cf,
            [0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b],
        ),
        "JFIF Media",
    ),
    (
        guid(
            0x91bd_222c,
            0xf21c,
            0x497a,
            [0x8b, 0x6d, 0x5a, 0xa8, 0x6b, 0xfc, 0x01, 0x85],
        ),
        "File Transfer Media",
    ),
    (
        guid(
            0x3afb_65e2,
            0x47ef,
            0x40f2,
            [0xac, 0x2c, 0x70, 0xa9, 0x0d, 0x71, 0xd3, 0x43],
        ),
        "Binary Media",
    ),
    (
        guid(
            0x20fb_5700,
            0x5b55,
            0x11cf,
            [0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b],
        ),
        "No Error Correction",
    ),
    (
        guid(
            0xbfc3_cd50,
            0x618f,
            0x11cf,
            [0x8b, 0xb2, 0x00, 0xaa, 0x00, 0xb4, 0xe2, 0x20],
        ),
        "Audio Spread",
    ),
    (
        guid(
            0xabd3_d211,
            0xa9ba,
            0x11cf,
            [0x8e, 0xe6, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65],
        ),
        "Reserved 1",
    ),
];

fn guid_name(g: &Guid) -> Option<&'static str> {
    NAMES.iter().find(|(k, _)| k == g).map(|(_, n)| *n)
}

/// The header GUID as stored on disk.
const HEADER_BYTES: &[u8] = b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c";
const VIDEO_BYTES: &[u8] = b"\xc0\xef\x19\xbc\x4d\x5b\xcf\x11\xa8\xfd\x00\x80\x5f\x5c\x44\x2b";
const AUDIO_BYTES: &[u8] = b"\x40\x9e\x69\xf8\x4d\x5b\xcf\x11\xa8\xfd\x00\x80\x5f\x5c\x44\x2b";

fn has(h: &Head<'_>, needle: &[u8]) -> bool {
    vidutil::find(h.data, needle).is_some()
}

pub static WMV: Format = Format {
    name: "wmv",
    title: "Windows Media Video",
    extensions: &["wmv", "asf"],
    mime: "video/x-ms-wmv",
    probe: Probe::Custom(|h| h.starts_with(HEADER_BYTES) && has(h, VIDEO_BYTES)),
    dissect: crate::expander!(dissect: Input),
};

pub static WMA: Format = Format {
    name: "wma",
    title: "Windows Media Audio",
    extensions: &["wma", "asf"],
    mime: "audio/x-ms-wma",
    probe: Probe::Custom(|h| {
        h.starts_with(HEADER_BYTES) && has(h, AUDIO_BYTES) && !has(h, VIDEO_BYTES)
    }),
    dissect: crate::expander!(dissect: Input),
};

pub static ASF: Format = Format {
    name: "asf",
    title: "Advanced Systems Format",
    extensions: &["asf", "wmv", "wma", "dvr-ms"],
    mime: "video/x-ms-asf",
    probe: Probe::Magic(&[(0, HEADER_BYTES)]),
    dissect: crate::expander!(dissect: Input),
};

const FILE_FLAGS: FlagTable = &[flag(0x1, "BROADCAST"), flag(0x2, "SEEKABLE")];

pub const AUDIO_FORMATS: EnumTable = &[
    (0x0001, "PCM"),
    (0x0002, "Microsoft ADPCM"),
    (0x0003, "IEEE float"),
    (0x0006, "A-law"),
    (0x0007, "µ-law"),
    (0x000a, "WMA Voice"),
    (0x0011, "IMA ADPCM"),
    (0x0050, "MPEG audio"),
    (0x0055, "MP3"),
    (0x00ff, "AAC"),
    (0x0160, "WMA v1"),
    (0x0161, "WMA v2"),
    (0x0162, "WMA Pro"),
    (0x0163, "WMA Lossless"),
    (0x1610, "HE-AAC"),
    (0x2000, "AC-3"),
    (0x2001, "DTS"),
    (0xfffe, "extensible"),
];

const VALUE_TYPES: EnumTable = &[
    (0, "Unicode string"),
    (1, "byte array"),
    (2, "BOOL"),
    (3, "DWORD"),
    (4, "QWORD"),
    (5, "WORD"),
    (6, "GUID"),
];

#[derive(Clone, Copy, Debug)]
struct Object {
    input: Input,
    span: Span,
    guid: Guid,
    depth: u32,
    /// Packet size from the file properties (for the data object).
    packet_size: u32,
}

const MAX_DEPTH: u32 = 8;

fn read_guid(d: &[u8], at: usize) -> Option<Guid> {
    let b: [u8; 16] = crate::bytes::array(d, at)?;
    let data4: [u8; 8] = crate::bytes::array(&b, 8)?;
    Some(Guid {
        data1: u32_le(&b, 0)?,
        data2: u16_le(&b, 4)?,
        data3: u16_le(&b, 6)?,
        data4,
    })
}

/// Lists the objects in `region`.
async fn objects(cx: &Cx, input: Input, region: Span, depth: u32, packet_size: u32) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Diagnostic::limit("objects nested too deeply").at(region));
    }
    let mut pos = 0u64;
    let mut packet_size = packet_size;
    while pos < region.len {
        let d = cx.read_avail(region.sub(pos, 24)).await?;
        let (Some(g), Some(size)) = (read_guid(&d, 0), u64_le(&d, 16)) else {
            cx.emit(Node::new("Trailing bytes").span(region.tail(pos)));
            break;
        };
        if size < 24 {
            cx.emit(Node::new("Invalid object").span(region.tail(pos)).diag(
                Diagnostic::malformed(format!("object size {size} is smaller than its header")),
            ));
            break;
        }
        let span = region.sub(pos, size);
        if g == FILE_PROPERTIES {
            let fp = cx.read_avail(span.sub(92, 4)).await?;
            packet_size = u32_le(&fp, 0).unwrap_or(packet_size);
        }
        let obj = Object {
            input,
            span,
            guid: g,
            depth,
            packet_size,
        };
        let name = guid_name(&g).map_or_else(|| g.to_string(), str::to_owned);
        let mut node = Node::new(name).span(span);
        if let Some(s) = describe(cx, &obj).await {
            node = node.summary(s);
        }
        if span.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, size),
                span.len,
            ));
        }
        cx.push(node.lazy(crate::expander!(self::expand_object: Object), obj))
            .await;
        pos = pos.saturating_add(size);
    }
    Ok(())
}

async fn describe(cx: &Cx, obj: &Object) -> Option<String> {
    let d = cx.read_avail(obj.span.sub(0, 0x400)).await.ok()?;
    let g = obj.guid;
    if g == HEADER {
        Some(format!("{} objects", u32_le(&d, 24)?))
    } else if g == DATA {
        Some(format!("{} packets", u64_le(&d, 40)?))
    } else if g == FILE_PROPERTIES {
        let play = u64_le(&d, 64)?;
        let preroll = u64_le(&d, 80)?;
        Some(vidutil::seconds_ms((play / 10_000).saturating_sub(preroll)))
    } else if g == STREAM_PROPERTIES {
        Some(stream_summary(&d)?)
    } else if g == CONTENT_DESCRIPTION {
        let title_len = usize::from(u16_le(&d, 24)?);
        let title = crate::text::utf16(d.get(34..34usize.saturating_add(title_len))?, LE);
        Some(title.trim_end_matches('\0').to_owned()).filter(|t| !t.is_empty())
    } else {
        None
    }
}

/// "#1 video: WMV1 16×16" or "#2 audio: WMA v1, 1 ch, 8000 Hz".
fn stream_summary(d: &[u8]) -> Option<String> {
    let kind = read_guid(d, 24)?;
    let number = u16_le(d, 72)? & 0x7f;
    let ts = d.get(78..)?;
    if kind == VIDEO_MEDIA {
        let w = u32_le(ts, 0)?;
        let h = u32_le(ts, 4)?;
        let fourcc = vidutil::fourcc(ts.get(27..31)?);
        Some(format!("#{number} video: {fourcc} {w}×{h}"))
    } else if kind == AUDIO_MEDIA {
        let tag = u16_le(ts, 0)?;
        Some(format!(
            "#{number} audio: {}, {} ch, {} Hz",
            vidutil::lookup_or(AUDIO_FORMATS, tag.into()),
            u16_le(ts, 2)?,
            u32_le(ts, 4)?
        ))
    } else {
        Some(format!(
            "#{number} {}",
            guid_name(&kind).unwrap_or("stream").to_lowercase()
        ))
    }
}

async fn expand_object(cx: Cx, obj: Object) -> Result<()> {
    let block = cx.block(obj.span.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.guid("Object ID")
        .with(|g, n| match guid_name(g) {
            Some(name) => n.summary(name),
            None => n,
        })
        .emit()?;
    f.u64("Object size").emit()?;
    let body = obj.span.tail(24);
    let g = obj.guid;
    if g == HEADER {
        let b = cx.block(body.sub(0, 0x10000)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        f.u32("Number of header objects").emit()?;
        f.u8("Reserved 1").emit()?;
        f.u8("Reserved 2").emit()?;
        objects(
            &cx,
            obj.input,
            body.tail(6),
            obj.depth.saturating_add(1),
            obj.packet_size,
        )
        .await?;
    } else if g == HEADER_EXTENSION {
        let b = cx.block(body.sub(0, 0x10000)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        f.guid("Reserved field 1").emit()?;
        f.u16("Reserved field 2").emit()?;
        f.u32("Header extension data size").emit()?;
        objects(
            &cx,
            obj.input,
            body.tail(22),
            obj.depth.saturating_add(1),
            obj.packet_size,
        )
        .await?;
    } else if g == DATA {
        let b = cx.block(body.sub(0, 26)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        f.guid("File ID").emit()?;
        let n = f.u64("Total data packets").emit()?;
        f.u16("Reserved").emit()?;
        let packets = body.tail(26);
        cx.emit(
            Node::new("Packets")
                .span(packets)
                .summary(format!("{n} packets of {} bytes", obj.packet_size))
                .lazy(expand_packets, (packets, n, obj.packet_size)),
        );
    } else {
        let b = cx.block(body.sub(0, 0x10000)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        decode_body(&mut f, &g)?;
        if f.remaining() > 0 && f.pos() > 0 {
            let rest = f.remaining();
            f.node(Node::new("Remaining data").span(f.peek_span(rest)));
        } else if f.pos() == 0 && !body.is_empty() {
            f.node(Node::new("Data").span(body));
        }
    }
    Ok(())
}

/// Decodes the bodies of leaf objects.
fn decode_body(f: &mut Fields<'_>, g: &Guid) -> Result<()> {
    if *g == FILE_PROPERTIES {
        f.guid("File ID").emit()?;
        f.u64("File size").emit()?;
        f.u64("Creation date").filetime().emit()?;
        f.u64("Data packets count").emit()?;
        f.u64("Play duration")
            .with(|&d, n| n.summary(vidutil::seconds_ms(d / 10_000)))
            .emit()?;
        f.u64("Send duration")
            .with(|&d, n| n.summary(vidutil::seconds_ms(d / 10_000)))
            .emit()?;
        f.u64("Preroll").desc("Milliseconds").emit()?;
        f.u32("Flags").flags(FILE_FLAGS).emit()?;
        f.u32("Minimum data packet size").emit()?;
        f.u32("Maximum data packet size").emit()?;
        f.u32("Maximum bitrate").emit()?;
    } else if *g == STREAM_PROPERTIES {
        let kind = f
            .guid("Stream type")
            .with(|g, n| match guid_name(g) {
                Some(name) => n.summary(name),
                None => n,
            })
            .emit()?;
        f.guid("Error correction type")
            .with(|g, n| match guid_name(g) {
                Some(name) => n.summary(name),
                None => n,
            })
            .emit()?;
        f.u64("Time offset").emit()?;
        let ts_len = f.u32("Type-specific data length").emit()?;
        let ec_len = f.u32("Error correction data length").emit()?;
        f.u16("Flags")
            .hex()
            .with(|&v, n| {
                n.summary(format!(
                    "stream {}{}",
                    v & 0x7f,
                    if v & 0x8000 != 0 { ", encrypted" } else { "" }
                ))
            })
            .emit()?;
        f.u32("Reserved").emit()?;
        let end = f.pos().saturating_add(ts_len.into());
        if kind == AUDIO_MEDIA {
            waveformatex(f)?;
        } else if kind == VIDEO_MEDIA {
            f.u32("Encoded image width").emit()?;
            f.u32("Encoded image height").emit()?;
            f.u8("Reserved flags").emit()?;
            f.u16("Format data size").emit()?;
            bitmapinfoheader(f)?;
        }
        if f.pos() < end {
            let n = end.saturating_sub(f.pos());
            f.bytes("Type-specific data", n).emit()?;
        }
        f.seek(end);
        if ec_len > 0 {
            f.bytes("Error correction data", ec_len.into()).emit()?;
        }
    } else if *g == CONTENT_DESCRIPTION {
        let mut lens = [0u16; 5];
        for (slot, name) in lens.iter_mut().zip([
            "Title length",
            "Author length",
            "Copyright length",
            "Description length",
            "Rating length",
        ]) {
            *slot = f.u16(name).emit()?;
        }
        for (len, name) in
            lens.iter()
                .zip(["Title", "Author", "Copyright", "Description", "Rating"])
        {
            f.utf16(name, u64::from(*len / 2)).emit()?;
        }
    } else if *g == EXTENDED_CONTENT {
        let n = f.u16("Content descriptors count").emit()?;
        for _ in 0..n {
            if f.remaining() < 6 {
                break;
            }
            let start = f.pos();
            let at = f.peek_span(0);
            let name_len = f.u16("Name length").get()?;
            let name = f.utf16("Name", u64::from(name_len / 2)).get()?;
            let kind = f.u16("Value type").get()?;
            let len = f.u16("Value length").get()?;
            let value = typed_value(f, kind, len.into())?;
            let span = Span::new(at.source, at.offset, f.pos().saturating_sub(start));
            f.node(value.map_or_else(
                || Node::new(name.clone()).span(span),
                |v| Node::new(name.clone()).span(span).value(v),
            ));
        }
    } else if *g == METADATA || *g == METADATA_LIBRARY {
        let n = f.u16("Description records count").emit()?;
        for _ in 0..n {
            if f.remaining() < 12 {
                break;
            }
            let start = f.pos();
            let at = f.peek_span(0);
            f.u16("Language list index").get()?;
            let stream = f.u16("Stream number").get()?;
            let name_len = f.u16("Name length").get()?;
            let kind = f.u16("Data type").get()?;
            let len = f.u32("Data length").get()?;
            let name = f.utf16("Name", u64::from(name_len / 2)).get()?;
            let value = typed_value(f, kind, len.into())?;
            let span = Span::new(at.source, at.offset, f.pos().saturating_sub(start));
            let mut node = Node::new(name).span(span);
            if let Some(v) = value {
                node = node.value(v);
            }
            if stream != 0 {
                node = node.summary(format!("stream {stream}"));
            }
            f.node(node);
        }
    } else if *g == CODEC_LIST {
        f.guid("Reserved").emit()?;
        let n = f.u32("Codec entries count").emit()?;
        for _ in 0..n {
            if f.remaining() < 6 {
                break;
            }
            f.u16("Type")
                .with(|&t, n| {
                    n.summary(match t {
                        1 => "video",
                        2 => "audio",
                        _ => "unknown",
                    })
                })
                .emit()?;
            let len = f.u16("Codec name length").emit()?;
            f.utf16("Codec name", len.into()).emit()?;
            let len = f.u16("Codec description length").emit()?;
            f.utf16("Codec description", len.into()).emit()?;
            let len = f.u16("Codec information length").emit()?;
            f.bytes("Codec information", len.into()).emit()?;
        }
    } else if *g == STREAM_BITRATES {
        let n = f.u16("Bitrate records count").emit()?;
        for _ in 0..n {
            if f.remaining() < 6 {
                break;
            }
            f.u16("Stream number").emit()?;
            f.u32("Average bitrate").emit()?;
        }
    } else if *g == LANGUAGE_LIST {
        let n = f.u16("Language ID records count").emit()?;
        for _ in 0..n {
            let len = f.u8("Language ID length").emit()?;
            f.utf16("Language ID", u64::from(len / 2)).emit()?;
        }
    } else if *g == SIMPLE_INDEX {
        f.guid("File ID").emit()?;
        f.u64("Index entry time interval").emit()?;
        f.u32("Maximum packet count").emit()?;
        let n = f.u32("Index entries count").emit()?;
        let rest = f.remaining();
        f.node(
            Node::new("Index entries")
                .span(f.peek_span(rest))
                .summary(format!("{n} entries")),
        );
        f.skip(rest);
    } else if *g == EXTENDED_STREAM {
        f.u64("Start time").emit()?;
        f.u64("End time").emit()?;
        f.u32("Data bitrate").emit()?;
        f.u32("Buffer size").emit()?;
        f.u32("Initial buffer fullness").emit()?;
        f.u32("Alternate data bitrate").emit()?;
        f.u32("Alternate buffer size").emit()?;
        f.u32("Alternate initial buffer fullness").emit()?;
        f.u32("Maximum object size").emit()?;
        f.u32("Flags").hex().emit()?;
        f.u16("Stream number").emit()?;
        f.u16("Stream language ID index").emit()?;
        f.u64("Average time per frame")
            .with(|&t, n| {
                if t > 0 {
                    n.summary(format!("{} fps", vidutil::num(10_000_000.0 / t as f64)))
                } else {
                    n
                }
            })
            .emit()?;
        f.u16("Stream name count").emit()?;
        f.u16("Payload extension system count").emit()?;
    }
    Ok(())
}

/// A typed value (extended content / metadata descriptors).
fn typed_value(f: &mut Fields<'_>, kind: u16, len: u64) -> Result<Option<Value>> {
    let bytes = f.bytes("Value", len).get()?;
    Ok(Some(match kind {
        0 => Value::Text(
            crate::text::utf16(&bytes, LE)
                .trim_end_matches('\0')
                .to_owned(),
        ),
        2 => Value::Bool(bytes.iter().any(|&b| b != 0)),
        3..=5 => Value::UInt {
            value: bytes
                .iter()
                .rev()
                .fold(0u64, |a, &b| (a << 8) | u64::from(b)),
            bits: u8::try_from(len.saturating_mul(8).min(64)).unwrap_or(64),
            radix: crate::value::Radix::Dec,
        },
        _ if bytes.len() <= 32 => Value::Bytes(bytes),
        _ => {
            return Ok(Some(Value::Text(format!(
                "{} bytes ({})",
                len,
                vidutil::lookup_or(VALUE_TYPES, kind.into())
            ))));
        }
    }))
}

/// WAVEFORMATEX, as used by ASF and AVI audio streams.
pub fn waveformatex(f: &mut Fields<'_>) -> Result<()> {
    f.u16("Format tag").enumeration(AUDIO_FORMATS).emit()?;
    f.u16("Channels").emit()?;
    f.u32("Samples per second").emit()?;
    f.u32("Average bytes per second").emit()?;
    f.u16("Block alignment").emit()?;
    f.u16("Bits per sample").emit()?;
    if f.remaining() >= 2 {
        let n = f.u16("Codec-specific data size").emit()?;
        if n > 0 {
            f.bytes("Codec-specific data", n.into()).emit()?;
        }
    }
    Ok(())
}

/// BITMAPINFOHEADER, as used by ASF and AVI video streams.
pub fn bitmapinfoheader(f: &mut Fields<'_>) -> Result<()> {
    let size = f.u32("Header size").emit()?;
    let start = f.pos().saturating_sub(4);
    f.i32("Image width").emit()?;
    f.i32("Image height").emit()?;
    f.u16("Planes").emit()?;
    f.u16("Bits per pixel").emit()?;
    f.ascii("Compression ID", 4)
        .with(|c, n| match vidutil::codec_name(c.as_bytes()) {
            Some(name) => n.summary(name),
            None => n,
        })
        .emit()?;
    f.u32("Image size").emit()?;
    f.i32("Horizontal pixels per meter").emit()?;
    f.i32("Vertical pixels per meter").emit()?;
    f.u32("Colors used").emit()?;
    f.u32("Important colors").emit()?;
    let end = start.saturating_add(size.into());
    if end > f.pos() {
        let n = end.saturating_sub(f.pos());
        f.bytes("Codec-specific data", n).emit()?;
    }
    Ok(())
}

const PAGE: u64 = 64;

async fn expand_packets(cx: Cx, (span, declared, size): (Span, u64, u32)) -> Result<()> {
    let size = u64::from(size);
    if size == 0 {
        cx.emit(Node::new("Packet data").span(span));
        return Ok(());
    }
    let count = span.len.checked_div(size).unwrap_or(0).min(declared.max(1));
    cx.set_count(Count::Exact(count));
    let mut i = 0u64;
    while i < count {
        let n = count.saturating_sub(i).min(PAGE);
        let page = span.sub(i.saturating_mul(size), n.saturating_mul(size));
        let data = cx.read_avail(page).await?;
        for j in 0..n {
            let at = vidutil::us(j.saturating_mul(size));
            let p = data.get(at..).unwrap_or_default();
            let pspan = page.sub(j.saturating_mul(size), size);
            let mut node = Node::new(format!("Packet {}", i.saturating_add(j))).span(pspan);
            if let Some(s) = packet_summary(p) {
                node = node.summary(s);
            }
            cx.push(node).await;
        }
        i = i.saturating_add(n);
    }
    let rest = span.tail(count.saturating_mul(size));
    if !rest.is_empty() {
        cx.emit(Node::new("Trailing data").span(rest));
    }
    Ok(())
}

/// Send time and payload count from a data packet's parsing information.
fn packet_summary(p: &[u8]) -> Option<String> {
    let mut at = 0usize;
    let first = *p.first()?;
    if first & 0x80 != 0 {
        at = 1usize.saturating_add(usize::from(first & 0x0f));
    }
    let flags = *p.get(at)?;
    at = at.saturating_add(2);
    let width = |t: u8| match t & 3 {
        1 => 1usize,
        2 => 2,
        3 => 4,
        _ => 0,
    };
    at = at
        .saturating_add(width(flags >> 5))
        .saturating_add(width(flags >> 1))
        .saturating_add(width(flags >> 3));
    let send = u32_le(p, at)?;
    let duration = u16_le(p, at.saturating_add(4))?;
    let mut s = format!("send time {} ms, duration {duration} ms", send);
    if flags & 1 != 0 {
        let payloads = p.get(at.saturating_add(6)).map_or(0, |b| b & 0x3f);
        s = format!("{s}, {payloads} payloads");
    }
    Some(s)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut packet_size = 0;
    if let Some((s, size)) = file_summary(&cx, input.span).await {
        cx.annotate(s);
        packet_size = size;
    }
    objects(&cx, input, input.span, 0, packet_size).await
}

/// The file node's summary and the data packet size.
async fn file_summary(cx: &Cx, file: Span) -> Option<(String, u32)> {
    let d = cx.read_avail(file.sub(0, 30)).await.ok()?;
    let size = u64_le(&d, 16)?;
    let header = vidutil::read_small(cx, file.sub(30, size.saturating_sub(30)), 0x40000)
        .await
        .ok()?;
    let mut video = false;
    let mut audio = false;
    let mut streams = Vec::new();
    let mut duration = None;
    let mut title = None;
    let mut packet_size = 0;
    let mut at = 0usize;
    for _ in 0..256 {
        let (Some(g), Some(len)) = (
            read_guid(&header, at),
            u64_le(&header, at.saturating_add(16)),
        ) else {
            break;
        };
        let len = usize::try_from(len).ok()?;
        let obj = header.get(at..at.saturating_add(len).min(header.len()))?;
        if g == STREAM_PROPERTIES {
            let kind = read_guid(obj, 24);
            video |= kind == Some(VIDEO_MEDIA);
            audio |= kind == Some(AUDIO_MEDIA);
            if let Some(s) = stream_summary(obj) {
                streams.push(
                    s.split_once(": ")
                        .map_or(s.clone(), |(_, rest)| rest.to_owned()),
                );
            }
        } else if g == FILE_PROPERTIES {
            let play = u64_le(obj, 64)?;
            let preroll = u64_le(obj, 80)?;
            duration = Some(vidutil::seconds_ms((play / 10_000).saturating_sub(preroll)));
            packet_size = u32_le(obj, 92).unwrap_or(0);
        } else if g == CONTENT_DESCRIPTION {
            let title_len = usize::from(u16_le(obj, 24)?);
            let t = crate::text::utf16(obj.get(34..34usize.saturating_add(title_len))?, LE);
            let t = t.trim_end_matches('\0').to_owned();
            if !t.is_empty() {
                title = Some(t);
            }
        }
        if len < 24 {
            break;
        }
        at = at.saturating_add(len);
    }
    let kind = if video {
        "WMV"
    } else if audio {
        "WMA"
    } else {
        "ASF"
    };
    let mut parts = vec![kind.to_owned()];
    if !streams.is_empty() {
        parts.push(streams.join(" + "));
    }
    if let Some(d) = duration {
        parts.push(d);
    }
    if let Some(t) = title {
        parts.push(format!("\"{t}\""));
    }
    Some((parts.join(", "), packet_size))
}
