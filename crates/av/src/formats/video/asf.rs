//! Advanced Systems Format (ASF): WMV, WMA and plain ASF files.
//!
//! The file is a sequence of objects `GUID, size (u64), body`. The header
//! object holds metadata objects (file and stream properties, content
//! descriptions, codec list, markers, script commands, header extension
//! with extended stream properties, language list, metadata and index
//! parameters); the data object holds fixed-size packets, listed in pages
//! and decoded down to their payload headers; the index objects follow.

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::{Block, Cx};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::audio::id3::PICTURE_TYPE;
use crate::formats::iff::wav;
use crate::formats::image::bmp;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::name_or;
use crate::formats::util::vidutil;
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, Radix, Value, field, flag};

const LE: Endian = Endian::Little;

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
    Guid {
        data1,
        data2,
        data3,
        data4,
    }
}

const A6D9: [u8; 8] = [0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c];
const C053: [u8; 8] = [0x8e, 0xe6, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65];
const A8FD: [u8; 8] = [0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b];
const A3A4: [u8; 8] = [0xa3, 0xa4, 0x00, 0xa0, 0xc9, 0x03, 0x48, 0xf6];
const B4B7: [u8; 8] = [0xb4, 0xb7, 0x00, 0xa0, 0xc9, 0x55, 0xfc, 0x6e];
const D11: [u8; 8] = [0x90, 0x34, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xbe];

const HEADER: Guid = guid(0x75b2_2630, 0x668e, 0x11cf, A6D9);
const DATA: Guid = guid(0x75b2_2636, 0x668e, 0x11cf, A6D9);
const SIMPLE_INDEX: Guid = guid(
    0x3300_0890,
    0xe5b1,
    0x11cf,
    [0x89, 0xf4, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xcb],
);
const INDEX: Guid = guid(0xd6e2_29d3, 0x35da, 0x11d1, D11);
const MEDIA_OBJECT_INDEX: Guid = guid(
    0xfeb1_03f8,
    0x12ad,
    0x4c64,
    [0x84, 0x0f, 0x2a, 0x1d, 0x2f, 0x7a, 0xd4, 0x8c],
);
const TIMECODE_INDEX: Guid = guid(
    0x3cb7_3fd0,
    0x0c4a,
    0x4803,
    [0x95, 0x3d, 0xed, 0xf7, 0xb6, 0x22, 0x8f, 0x0c],
);
const FILE_PROPERTIES: Guid = guid(
    0x8cab_dca1,
    0xa947,
    0x11cf,
    [0x8e, 0xe4, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65],
);
const STREAM_PROPERTIES: Guid = guid(0xb7dc_0791, 0xa9b7, 0x11cf, C053);
const HEADER_EXTENSION: Guid = guid(
    0x5fbf_03b5,
    0xa92e,
    0x11cf,
    [0x8e, 0xe3, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65],
);
const CODEC_LIST: Guid = guid(0x86d1_5240, 0x311d, 0x11d0, A3A4);
const SCRIPT_COMMAND: Guid = guid(
    0x1efb_1a30,
    0x0b62,
    0x11d0,
    [0xa3, 0x9b, 0x00, 0xa0, 0xc9, 0x03, 0x48, 0xf6],
);
const MARKER: Guid = guid(0xf487_cd01, 0xa951, 0x11cf, C053);
const BITRATE_MUTUAL_EXCLUSION: Guid = guid(0xd6e2_29dc, 0x35da, 0x11d1, D11);
const ERROR_CORRECTION: Guid = guid(0x75b2_2635, 0x668e, 0x11cf, A6D9);
const CONTENT_DESCRIPTION: Guid = guid(0x75b2_2633, 0x668e, 0x11cf, A6D9);
const EXTENDED_CONTENT: Guid = guid(
    0xd2d0_a440,
    0xe307,
    0x11d2,
    [0x97, 0xf0, 0x00, 0xa0, 0xc9, 0x5e, 0xa8, 0x50],
);
const CONTENT_BRANDING: Guid = guid(0x2211_b3fa, 0xbd23, 0x11d2, B4B7);
const STREAM_BITRATES: Guid = guid(
    0x7bf8_75ce,
    0x468d,
    0x11d1,
    [0x8d, 0x82, 0x00, 0x60, 0x97, 0xc9, 0xa2, 0xb2],
);
const CONTENT_ENCRYPTION: Guid = guid(0x2211_b3fb, 0xbd23, 0x11d2, B4B7);
const EXTENDED_CONTENT_ENCRYPTION: Guid = guid(
    0x298a_e614,
    0x2622,
    0x4c17,
    [0xb9, 0x35, 0xda, 0xe0, 0x7e, 0xe9, 0x28, 0x9c],
);
const DIGITAL_SIGNATURE: Guid = guid(0x2211_b3fc, 0xbd23, 0x11d2, B4B7);
const PADDING: Guid = guid(
    0x1806_d474,
    0xcadf,
    0x4509,
    [0xa4, 0xba, 0x9a, 0xab, 0xcb, 0x96, 0xaa, 0xe8],
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
const ADVANCED_MUTUAL_EXCLUSION: Guid = guid(
    0xa086_49cf,
    0x4775,
    0x4670,
    [0x8a, 0x16, 0x6e, 0x35, 0x35, 0x75, 0x66, 0xcd],
);
const GROUP_MUTUAL_EXCLUSION: Guid = guid(
    0xd146_5a40,
    0x5a79,
    0x4338,
    [0xb7, 0x1b, 0xe3, 0x6b, 0x8f, 0xd6, 0xc2, 0x49],
);
const STREAM_PRIORITIZATION: Guid = guid(
    0xd4fe_d15b,
    0x88d3,
    0x454f,
    [0x81, 0xf0, 0xed, 0x5c, 0x45, 0x99, 0x9e, 0x24],
);
const BANDWIDTH_SHARING: Guid = guid(
    0xa696_09e6,
    0x517b,
    0x11d2,
    [0xb6, 0xaf, 0x00, 0xc0, 0x4f, 0xd9, 0x08, 0xe9],
);
const INDEX_PARAMETERS: Guid = guid(0xd6e2_29df, 0x35da, 0x11d1, D11);
const MEDIA_OBJECT_INDEX_PARAMETERS: Guid = guid(
    0x6b20_3bad,
    0x3f11,
    0x48e4,
    [0xac, 0xa8, 0xd7, 0x61, 0x3d, 0xe2, 0xcf, 0xa7],
);
const TIMECODE_INDEX_PARAMETERS: Guid = guid(
    0xf55e_496d,
    0x9797,
    0x4b5d,
    [0x8c, 0x8b, 0x60, 0x4d, 0xfe, 0x9b, 0xfb, 0x24],
);
const COMPATIBILITY: Guid = guid(
    0x26f1_8b5d,
    0x4584,
    0x47ec,
    [0x9f, 0x5f, 0x0e, 0x65, 0x1f, 0x04, 0x52, 0xc9],
);

const AUDIO_MEDIA: Guid = guid(0xf869_9e40, 0x5b4d, 0x11cf, A8FD);
const VIDEO_MEDIA: Guid = guid(0xbc19_efc0, 0x5b4d, 0x11cf, A8FD);
const JFIF_MEDIA: Guid = guid(0xb61b_e100, 0x5b4e, 0x11cf, A8FD);
const DEGRADABLE_JPEG_MEDIA: Guid = guid(
    0x3590_7de0,
    0xe415,
    0x11cf,
    [0xa9, 0x17, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b],
);
const BINARY_MEDIA: Guid = guid(
    0x3afb_65e2,
    0x47ef,
    0x40f2,
    [0xac, 0x2c, 0x70, 0xa9, 0x0d, 0x71, 0xd3, 0x43],
);
const AUDIO_SPREAD: Guid = guid(
    0xbfc3_cd50,
    0x618f,
    0x11cf,
    [0x8b, 0xb2, 0x00, 0xaa, 0x00, 0xb4, 0xe2, 0x20],
);

const NAMES: &[(Guid, &str)] = &[
    (HEADER, "Header"),
    (DATA, "Data"),
    (SIMPLE_INDEX, "Simple Index"),
    (INDEX, "Index"),
    (MEDIA_OBJECT_INDEX, "Media Object Index"),
    (TIMECODE_INDEX, "Timecode Index"),
    (FILE_PROPERTIES, "File Properties"),
    (STREAM_PROPERTIES, "Stream Properties"),
    (HEADER_EXTENSION, "Header Extension"),
    (CODEC_LIST, "Codec List"),
    (SCRIPT_COMMAND, "Script Command"),
    (MARKER, "Marker"),
    (BITRATE_MUTUAL_EXCLUSION, "Bitrate Mutual Exclusion"),
    (ERROR_CORRECTION, "Error Correction"),
    (CONTENT_DESCRIPTION, "Content Description"),
    (EXTENDED_CONTENT, "Extended Content Description"),
    (CONTENT_BRANDING, "Content Branding"),
    (STREAM_BITRATES, "Stream Bitrate Properties"),
    (CONTENT_ENCRYPTION, "Content Encryption"),
    (EXTENDED_CONTENT_ENCRYPTION, "Extended Content Encryption"),
    (DIGITAL_SIGNATURE, "Digital Signature"),
    (PADDING, "Padding"),
    (EXTENDED_STREAM, "Extended Stream Properties"),
    (ADVANCED_MUTUAL_EXCLUSION, "Advanced Mutual Exclusion"),
    (GROUP_MUTUAL_EXCLUSION, "Group Mutual Exclusion"),
    (STREAM_PRIORITIZATION, "Stream Prioritization"),
    (BANDWIDTH_SHARING, "Bandwidth Sharing"),
    (LANGUAGE_LIST, "Language List"),
    (METADATA, "Metadata"),
    (METADATA_LIBRARY, "Metadata Library"),
    (INDEX_PARAMETERS, "Index Parameters"),
    (
        MEDIA_OBJECT_INDEX_PARAMETERS,
        "Media Object Index Parameters",
    ),
    (TIMECODE_INDEX_PARAMETERS, "Timecode Index Parameters"),
    (COMPATIBILITY, "Compatibility"),
    (
        guid(
            0x4305_8533,
            0x6981,
            0x49e6,
            [0x9b, 0x74, 0xad, 0x12, 0xcb, 0x86, 0xd5, 0x8c],
        ),
        "Advanced Content Encryption",
    ),
    (
        guid(
            0xd9aa_de20,
            0x7c17,
            0x4f9c,
            [0xbc, 0x28, 0x85, 0x55, 0xdd, 0x98, 0xe2, 0xa2],
        ),
        "Index Placeholder",
    ),
    (AUDIO_MEDIA, "Audio Media"),
    (VIDEO_MEDIA, "Video Media"),
    (guid(0x59da_cfc0, 0x59e6, 0x11d0, A3A4), "Command Media"),
    (JFIF_MEDIA, "JFIF Media"),
    (DEGRADABLE_JPEG_MEDIA, "Degradable JPEG Media"),
    (
        guid(
            0x91bd_222c,
            0xf21c,
            0x497a,
            [0x8b, 0x6d, 0x5a, 0xa8, 0x6b, 0xfc, 0x01, 0x85],
        ),
        "File Transfer Media",
    ),
    (BINARY_MEDIA, "Binary Media"),
    (
        guid(0x20fb_5700, 0x5b55, 0x11cf, A8FD),
        "No Error Correction",
    ),
    (AUDIO_SPREAD, "Audio Spread"),
    (guid(0xabd3_d211, 0xa9ba, 0x11cf, C053), "Reserved 1"),
    (guid(0x86d1_5241, 0x311d, 0x11d0, A3A4), "Reserved 2"),
    (
        guid(
            0x4b1a_cbe3,
            0x100b,
            0x11d0,
            [0xa3, 0x9b, 0x00, 0xa0, 0xc9, 0x03, 0x48, 0xf6],
        ),
        "Reserved 3",
    ),
    (
        guid(
            0x4cfe_db20,
            0x75f6,
            0x11cf,
            [0x9c, 0x0f, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xcb],
        ),
        "Reserved 4",
    ),
    (guid(0xd6e2_2a00, 0x35da, 0x11d1, D11), "Mutex Language"),
    (guid(0xd6e2_2a01, 0x35da, 0x11d1, D11), "Mutex Bitrate"),
    (guid(0xd6e2_2a02, 0x35da, 0x11d1, D11), "Mutex Unknown"),
    (
        guid(
            0xaf60_60aa,
            0x5197,
            0x11d2,
            [0xb6, 0xaf, 0x00, 0xc0, 0x4f, 0xd9, 0x08, 0xe9],
        ),
        "Bandwidth Sharing Exclusive",
    ),
    (
        guid(
            0xaf60_60ab,
            0x5197,
            0x11d2,
            [0xb6, 0xaf, 0x00, 0xc0, 0x4f, 0xd9, 0x08, 0xe9],
        ),
        "Bandwidth Sharing Partial",
    ),
    (
        guid(
            0x3995_95ec,
            0x8667,
            0x4e2d,
            [0x8f, 0xdb, 0x98, 0x81, 0x4c, 0xe7, 0x6c, 0x1e],
        ),
        "Payload Extension: Timecode",
    ),
    (
        guid(
            0xe165_ec0e,
            0x19ed,
            0x45d7,
            [0xb4, 0xa7, 0x25, 0xcb, 0xd1, 0xe2, 0x8e, 0x9b],
        ),
        "Payload Extension: File Name",
    ),
    (
        guid(
            0xd590_dc20,
            0x07bc,
            0x436c,
            [0x9c, 0xf7, 0xf3, 0xbb, 0xfb, 0xf1, 0xa4, 0xdc],
        ),
        "Payload Extension: Content Type",
    ),
    (
        guid(
            0x1b1e_e554,
            0xf9ea,
            0x4bc8,
            [0x82, 0x1a, 0x37, 0x6b, 0x74, 0xe4, 0xc4, 0xb8],
        ),
        "Payload Extension: Pixel Aspect Ratio",
    ),
    (
        guid(
            0xc6bd_9450,
            0x867f,
            0x4907,
            [0x83, 0xa3, 0xc7, 0x79, 0x21, 0xb7, 0x33, 0xad],
        ),
        "Payload Extension: Sample Duration",
    ),
    (
        guid(
            0x6698_b84e,
            0x0afa,
            0x4330,
            [0xae, 0xb2, 0x1c, 0x0a, 0x98, 0xd7, 0xa4, 0x4d],
        ),
        "Payload Extension: Encryption Sample ID",
    ),
    (
        guid(
            0x00e1_af06,
            0x7bec,
            0x11d1,
            [0xa5, 0x82, 0x00, 0xc0, 0x4f, 0xc2, 0x9c, 0xfb],
        ),
        "Payload Extension: Degradable JPEG",
    ),
];

fn guid_name(g: &Guid) -> Option<&'static str> {
    NAMES.iter().find(|(k, _)| k == g).map(|(_, n)| *n)
}

fn named_guid(g: &Guid, n: Node) -> Node {
    match guid_name(g) {
        Some(name) => n.summary(name),
        None => n,
    }
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

const EXT_STREAM_FLAGS: FlagTable = &[
    flag(0x1, "RELIABLE"),
    flag(0x2, "SEEKABLE"),
    flag(0x4, "NO_CLEANPOINTS"),
    flag(0x8, "RESEND_LIVE_CLEANPOINTS"),
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

const INDEX_TYPES: EnumTable = &[
    (1, "nearest past data packet"),
    (2, "nearest past media object"),
    (3, "nearest past cleanpoint"),
];

const CODEC_TYPES: EnumTable = &[(1, "video"), (2, "audio"), (0xffff, "unknown")];

const PRIORITY_FLAGS: FlagTable = &[flag(1, "MANDATORY")];

const BANNER_TYPES: EnumTable = &[(0, "none"), (1, "bitmap"), (2, "JPEG"), (3, "GIF")];

#[derive(Clone, Copy, Debug)]
struct Object {
    input: Input,
    span: Span,
    guid: Guid,
    depth: u32,
    /// Packet size from the file properties (for the data object).
    packet_size: u32,
    /// The data object's packets (for the index objects).
    packets: Option<Span>,
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
async fn objects(
    cx: &Cx,
    input: Input,
    region: Span,
    depth: u32,
    packet_size: u32,
    packets: Option<Span>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Diagnostic::limit("objects nested too deeply").at(region));
    }
    let mut pos = 0u64;
    let mut packet_size = packet_size;
    let mut packets = packets;
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
        } else if g == DATA {
            packets = Some(span.tail(50));
        }
        let obj = Object {
            input,
            span,
            guid: g,
            depth,
            packet_size,
            packets,
        };
        let name = guid_name(&g).map_or_else(|| g.to_string(), str::to_owned);
        let mut node = Node::new(name).span(span);
        if let Some(s) = describe(cx, &obj).await {
            node = node.summary(s);
        }
        if let Some(d) = description(&g) {
            node = node.desc(d);
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

fn description(g: &Guid) -> Option<&'static str> {
    let d = match *g {
        HEADER => "Holds the objects that describe the file",
        DATA => "The data packets, of the size given in the file properties",
        SIMPLE_INDEX => "Packet to start from for each time interval of a video stream",
        INDEX => "Packet offsets for each time interval, per stream",
        FILE_PROPERTIES => "Global properties: size, duration, packet size, bitrate",
        STREAM_PROPERTIES => "One stream: its type and codec format",
        HEADER_EXTENSION => "Holds the objects added by later versions of the format",
        CODEC_LIST => "The codecs used, for display",
        MARKER => "Named positions (chapters)",
        SCRIPT_COMMAND => "Commands (URLs, captions) to run at given times",
        CONTENT_DESCRIPTION => "Title, author, copyright, description and rating",
        EXTENDED_CONTENT => "Name/value metadata (WM/ attributes)",
        STREAM_BITRATES => "Average bitrate of each stream",
        CONTENT_ENCRYPTION => "DRM (version 1) parameters",
        EXTENDED_CONTENT_ENCRYPTION => "DRM (version 7) parameters",
        EXTENDED_STREAM => "Additional stream properties: bitrates, frame rate, payload extensions",
        LANGUAGE_LIST => "Languages referred to by index from other objects",
        METADATA => "Per-stream name/value metadata",
        METADATA_LIBRARY => "Name/value metadata with large values (cover art)",
        INDEX_PARAMETERS => "How the Index object is built",
        PADDING => "Space reserved for editing the header",
        _ => return None,
    };
    Some(d)
}

async fn describe(cx: &Cx, obj: &Object) -> Option<String> {
    let d = cx.read_avail(obj.span.sub(0, 0x400)).await.ok()?;
    let g = obj.guid;
    if g == HEADER {
        Some(plural(u32_le(&d, 24)?, "object"))
    } else if g == DATA {
        Some(plural(u64_le(&d, 40)?, "packet"))
    } else if g == FILE_PROPERTIES {
        let play = u64_le(&d, 64)?;
        let preroll = u64_le(&d, 80)?;
        let mut s = vidutil::seconds_ms((play / 10_000).saturating_sub(preroll));
        let bitrate = u32_le(&d, 100)?;
        if bitrate > 0 {
            s.push_str(&format!(", up to {} kb/s", bitrate / 1000));
        }
        Some(s)
    } else if g == STREAM_PROPERTIES {
        stream_summary(&d)
    } else if g == CONTENT_DESCRIPTION {
        let title_len = usize::from(u16_le(&d, 24)?);
        let title = crate::text::utf16(d.get(34..34usize.saturating_add(title_len))?, LE);
        Some(title.trim_end_matches('\0').to_owned()).filter(|t| !t.is_empty())
    } else if g == EXTENDED_CONTENT || g == METADATA || g == METADATA_LIBRARY {
        Some(plural(u16_le(&d, 24)?, "attribute"))
    } else if g == CODEC_LIST {
        Some(plural(u32_le(&d, 40)?, "codec"))
    } else if g == MARKER {
        Some(plural(u32_le(&d, 40)?, "marker"))
    } else if g == SCRIPT_COMMAND {
        Some(plural(u16_le(&d, 40)?, "command"))
    } else if g == LANGUAGE_LIST {
        Some(plural(u16_le(&d, 24)?, "language"))
    } else if g == STREAM_BITRATES {
        Some(plural(u16_le(&d, 24)?, "stream"))
    } else if g == EXTENDED_STREAM {
        let number = u16_le(&d, 72)?;
        let per_frame = u64_le(&d, 76)?;
        let mut s = format!("stream {number}");
        if per_frame > 0 {
            s.push_str(&format!(
                ", {} fps",
                vidutil::num(10_000_000.0 / per_frame as f64)
            ));
        }
        let bitrate = u32_le(&d, 40)?;
        if bitrate > 0 {
            s.push_str(&format!(", {} kb/s", bitrate / 1000));
        }
        Some(s)
    } else if g == SIMPLE_INDEX {
        Some(entry_count(u32_le(&d, 52)?.into()))
    } else if g == INDEX_PARAMETERS
        || g == MEDIA_OBJECT_INDEX_PARAMETERS
        || g == TIMECODE_INDEX_PARAMETERS
    {
        Some(plural(u16_le(&d, 28)?, "index specifier"))
    } else if g == PADDING {
        Some(format!("{} bytes", obj.span.len.saturating_sub(24)))
    } else {
        None
    }
}

/// "#1 video: Windows Media Video 8 16×16" or "#2 audio: WMA v2, mono, 8000 Hz".
fn stream_summary(d: &[u8]) -> Option<String> {
    let kind = read_guid(d, 24)?;
    let number = u16_le(d, 72)? & 0x7f;
    let ts = d.get(78..)?;
    if kind == VIDEO_MEDIA {
        let w = u32_le(ts, 0)?;
        let h = u32_le(ts, 4)?;
        let codec = compression_name(ts.get(27..31)?);
        Some(format!("#{number} video: {codec} {w}×{h}"))
    } else if kind == AUDIO_MEDIA {
        let w = wav::peek_format(ts)?;
        Some(format!(
            "#{number} audio: {}, {}, {} Hz",
            w.codec_name(),
            channel_word(w.channels),
            w.rate
        ))
    } else {
        Some(format!(
            "#{number} {}",
            guid_name(&kind).unwrap_or("stream").to_lowercase()
        ))
    }
}

/// "1 entry", "3 entries".
fn entry_count(n: u64) -> String {
    if n == 1 {
        "1 entry".to_owned()
    } else {
        format!("{n} entries")
    }
}

/// "WMV2 16×16", "WMA v2 mono 8000 Hz", for the file summary.
fn stream_short(d: &[u8]) -> Option<String> {
    let kind = read_guid(d, 24)?;
    let ts = d.get(78..)?;
    if kind == VIDEO_MEDIA {
        Some(format!(
            "{} {}×{}",
            compression_name(ts.get(27..31)?),
            u32_le(ts, 0)?,
            u32_le(ts, 4)?
        ))
    } else if kind == AUDIO_MEDIA {
        let w = wav::peek_format(ts)?;
        Some(format!(
            "{} {} {} Hz",
            w.codec_name(),
            channel_word(w.channels),
            w.rate
        ))
    } else {
        Some(guid_name(&kind).unwrap_or("stream").to_lowercase())
    }
}

fn channel_word(n: u16) -> String {
    match n {
        1 => "mono".to_owned(),
        2 => "stereo".to_owned(),
        6 => "5.1".to_owned(),
        8 => "7.1".to_owned(),
        n => format!("{n} ch"),
    }
}

async fn expand_object(cx: Cx, obj: Object) -> Result<()> {
    let block = cx.block(obj.span.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.guid("Object ID").with(named_guid).emit()?;
    f.u64("Object size").emit()?;
    let body = obj.span.tail(24);
    let g = obj.guid;
    if g == HEADER {
        let b = cx.block(body.sub(0, 6)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        f.u32("Number of header objects").emit()?;
        f.u8("Reserved 1").desc("Always 1").emit()?;
        f.u8("Reserved 2").desc("Always 2").emit()?;
        objects(
            &cx,
            obj.input,
            body.tail(6),
            obj.depth.saturating_add(1),
            obj.packet_size,
            obj.packets,
        )
        .await?;
    } else if g == HEADER_EXTENSION {
        let b = cx.block(body.sub(0, 22)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        f.guid("Reserved field 1").with(named_guid).emit()?;
        f.u16("Reserved field 2").desc("Always 6").emit()?;
        f.u32("Header extension data size").emit()?;
        objects(
            &cx,
            obj.input,
            body.tail(22),
            obj.depth.saturating_add(1),
            obj.packet_size,
            obj.packets,
        )
        .await?;
    } else if g == DATA {
        let b = cx.block(body.sub(0, 26)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        f.guid("File ID").emit()?;
        let n = f
            .u64("Total data packets")
            .desc("0 while broadcasting")
            .emit()?;
        f.u16("Reserved").hex().desc("Always 0x0101").emit()?;
        let packets = body.tail(26);
        cx.emit(
            Node::new("Packets")
                .span(packets)
                .summary(format!(
                    "{} of {} bytes",
                    plural(n, "packet"),
                    obj.packet_size
                ))
                .lazy(expand_packets, (packets, n, obj.packet_size)),
        );
    } else if g == SIMPLE_INDEX || g == INDEX || g == MEDIA_OBJECT_INDEX {
        index_object(&cx, &obj, body).await?;
    } else {
        let b = cx.block(body.sub(0, 0x10000)).await?;
        let mut f = Fields::emitting(&cx, &b, LE);
        decode_body(&mut f, &obj)?;
        let pos = f.pos();
        if g == EXTENDED_STREAM && pos < body.len {
            // An embedded Stream Properties object may follow.
            objects(
                &cx,
                obj.input,
                body.tail(pos),
                obj.depth.saturating_add(1),
                obj.packet_size,
                obj.packets,
            )
            .await?;
        } else if f.remaining() > 0 && pos > 0 {
            let rest = f.remaining();
            f.node(Node::new("Remaining data").span(f.peek_span(rest)));
        } else if pos == 0 && !body.is_empty() {
            f.node(Node::new("Data").span(body));
        }
    }
    Ok(())
}

/// A UTF-16 string whose byte length precedes it.
fn utf16_bytes(f: &mut Fields<'_>, name: &'static str, bytes: u64) -> Result<String> {
    let s = f.utf16(name, bytes / 2).emit()?;
    if bytes & 1 == 1 {
        f.skip(1);
    }
    Ok(s)
}

/// An entry of a variable-length list, emitted as a lazy group node: the
/// layout runs once silently to find its length, then again on expansion.
fn group(
    f: &mut Fields<'_>,
    name: impl Into<std::borrow::Cow<'static, str>>,
    layout: fn(&mut Fields<'_>) -> Result<Option<String>>,
) -> Result<()> {
    let start = f.pos();
    let mut silent = Fields::new(f.block(), LE);
    silent.seek(start);
    let summary = layout(&mut silent)?;
    let len = silent.pos().saturating_sub(start);
    let span = f.peek_span(len);
    let mut node = Node::new(name)
        .span(span)
        .lazy(expand_group, (span, layout));
    if let Some(s) = summary {
        node = node.summary(s);
    }
    f.node(node);
    f.skip(len);
    Ok(())
}

type GroupLayout = fn(&mut Fields<'_>) -> Result<Option<String>>;

async fn expand_group(cx: Cx, (span, layout): (Span, GroupLayout)) -> Result<()> {
    let block = cx.block(span).await?;
    layout(&mut Fields::emitting(&cx, &block, LE))?;
    Ok(())
}

/// A list of stream numbers, preceded by their count.
fn stream_numbers(f: &mut Fields<'_>) -> Result<()> {
    let n = f.u16("Stream count").emit()?;
    for _ in 0..n {
        if f.remaining() < 2 {
            break;
        }
        f.u16("Stream number").emit()?;
    }
    Ok(())
}

/// Decodes the bodies of leaf objects.
fn decode_body(f: &mut Fields<'_>, obj: &Object) -> Result<()> {
    let g = obj.guid;
    if g == FILE_PROPERTIES {
        f.guid("File ID").emit()?;
        f.u64("File size").emit()?;
        f.u64("Creation date").filetime().emit()?;
        f.u64("Data packets count").emit()?;
        f.u64("Play duration")
            .desc("100-ns units, preroll included")
            .with(|&d, n| n.summary(vidutil::seconds_ms(d / 10_000)))
            .emit()?;
        f.u64("Send duration")
            .desc("100-ns units")
            .with(|&d, n| n.summary(vidutil::seconds_ms(d / 10_000)))
            .emit()?;
        f.u64("Preroll")
            .desc("Milliseconds to buffer before playing; timestamps include it")
            .with(|&d, n| n.summary(format!("{d} ms")))
            .emit()?;
        f.u32("Flags").flags(FILE_FLAGS).emit()?;
        f.u32("Minimum data packet size").emit()?;
        f.u32("Maximum data packet size").emit()?;
        f.u32("Maximum bitrate")
            .with(|&b, n| n.summary(format!("{} kb/s", b / 1000)))
            .emit()?;
    } else if g == STREAM_PROPERTIES {
        stream_properties(f)?;
    } else if g == CONTENT_DESCRIPTION {
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
            utf16_bytes(f, name, u64::from(*len))?;
        }
    } else if g == EXTENDED_CONTENT {
        let n = f.u16("Content descriptors count").emit()?;
        for _ in 0..n {
            if f.remaining() < 6 {
                break;
            }
            attribute(f, obj, false)?;
        }
    } else if g == METADATA || g == METADATA_LIBRARY {
        let n = f.u16("Description records count").emit()?;
        for _ in 0..n {
            if f.remaining() < 12 {
                break;
            }
            attribute(f, obj, true)?;
        }
    } else if g == CODEC_LIST {
        f.guid("Reserved").with(named_guid).emit()?;
        let n = f.u32("Codec entries count").emit()?;
        for i in 0..n {
            if f.remaining() < 8 {
                break;
            }
            group(f, format!("Codec {}", i.saturating_add(1)), codec_entry)?;
        }
    } else if g == STREAM_BITRATES {
        let n = f.u16("Bitrate records count").emit()?;
        for _ in 0..n {
            if f.remaining() < 6 {
                break;
            }
            f.u16("Flags")
                .hex()
                .with(|&v, n| n.summary(format!("stream {}", v & 0x7f)))
                .emit()?;
            f.u32("Average bitrate")
                .with(|&b, n| n.summary(format!("{} kb/s", vidutil::num(f64::from(b) / 1000.0))))
                .emit()?;
        }
    } else if g == LANGUAGE_LIST {
        let n = f.u16("Language ID records count").emit()?;
        for _ in 0..n {
            if f.remaining() < 1 {
                break;
            }
            let len = f.u8("Language ID length").emit()?;
            utf16_bytes(f, "Language ID", len.into())?;
        }
    } else if g == EXTENDED_STREAM {
        extended_stream(f)?;
    } else if g == MARKER {
        f.guid("Reserved").with(named_guid).emit()?;
        let n = f.u32("Markers count").emit()?;
        f.u16("Reserved 2").emit()?;
        let len = f.u16("Name length").emit()?;
        utf16_bytes(f, "Name", len.into())?;
        for i in 0..n {
            if f.remaining() < 30 {
                break;
            }
            group(f, format!("Marker {}", i.saturating_add(1)), marker)?;
        }
    } else if g == SCRIPT_COMMAND {
        f.guid("Reserved").with(named_guid).emit()?;
        let commands = f.u16("Commands count").emit()?;
        let types = f.u16("Command types count").emit()?;
        for _ in 0..types {
            if f.remaining() < 2 {
                break;
            }
            let len = f.u16("Command type name length").emit()?;
            f.utf16("Command type name", len.into()).emit()?;
        }
        for i in 0..commands {
            if f.remaining() < 8 {
                break;
            }
            group(
                f,
                format!("Command {}", i.saturating_add(1)),
                script_command,
            )?;
        }
    } else if g == INDEX_PARAMETERS
        || g == MEDIA_OBJECT_INDEX_PARAMETERS
        || g == TIMECODE_INDEX_PARAMETERS
    {
        f.u32("Index entry time interval")
            .with(|&v, n| n.summary(format!("{v} ms")))
            .emit()?;
        let n = f.u16("Index specifiers count").emit()?;
        for _ in 0..n {
            if f.remaining() < 4 {
                break;
            }
            f.u16("Stream number").emit()?;
            f.u16("Index type").enumeration(INDEX_TYPES).emit()?;
        }
    } else if g == BITRATE_MUTUAL_EXCLUSION || g == ADVANCED_MUTUAL_EXCLUSION {
        f.guid("Exclusion type").with(named_guid).emit()?;
        stream_numbers(f)?;
    } else if g == GROUP_MUTUAL_EXCLUSION {
        f.guid("Exclusion type").with(named_guid).emit()?;
        let n = f.u16("Records count").emit()?;
        for _ in 0..n {
            if f.remaining() < 2 {
                break;
            }
            stream_numbers(f)?;
        }
    } else if g == STREAM_PRIORITIZATION {
        let n = f.u16("Priority records count").emit()?;
        for _ in 0..n {
            if f.remaining() < 4 {
                break;
            }
            f.u16("Stream number").emit()?;
            f.u16("Flags").flags(PRIORITY_FLAGS).emit()?;
        }
    } else if g == BANDWIDTH_SHARING {
        f.guid("Sharing type").with(named_guid).emit()?;
        f.u32("Data bitrate").emit()?;
        f.u32("Buffer size").desc("Milliseconds").emit()?;
        stream_numbers(f)?;
    } else if g == ERROR_CORRECTION {
        f.guid("Error correction type").with(named_guid).emit()?;
        let n = f.u32("Error correction data length").emit()?;
        f.bytes("Error correction data", n.into()).emit()?;
    } else if g == CONTENT_ENCRYPTION {
        let n = f.u32("Secret data length").emit()?;
        f.bytes("Secret data", n.into()).emit()?;
        let n = f.u32("Protection type length").emit()?;
        f.ascii("Protection type", n.into()).emit()?;
        let n = f.u32("Key ID length").emit()?;
        f.ascii("Key ID", n.into()).emit()?;
        let n = f.u32("License URL length").emit()?;
        f.ascii("License URL", n.into()).emit()?;
    } else if g == EXTENDED_CONTENT_ENCRYPTION {
        let n = f.u32("Data size").emit()?;
        let at = f.pos();
        let bytes = f.bytes("Data", n.into()).get()?;
        let text = crate::text::utf16(&bytes, LE);
        let span = f.block().span.sub(at, n.into());
        f.node(if text.starts_with('<') {
            Node::new("Data")
                .span(span)
                .value(Value::Text(text.trim_end_matches('\0').to_owned()))
        } else {
            Node::new("Data").span(span).value(Value::Bytes(bytes))
        });
    } else if g == DIGITAL_SIGNATURE {
        f.u32("Signature type").emit()?;
        let n = f.u32("Signature data length").emit()?;
        f.bytes("Signature data", n.into()).emit()?;
    } else if g == CONTENT_BRANDING {
        f.u32("Banner image type")
            .enumeration(BANNER_TYPES)
            .emit()?;
        let n = f.u32("Banner image data size").emit()?;
        let at = f.pos();
        f.skip(n.into());
        if n > 0 {
            let span = f.block().span.sub(at, n.into());
            f.node(embedded("Banner image", obj.input.nested(span)));
        }
        let n = f.u32("Banner image URL length").emit()?;
        f.ascii("Banner image URL", n.into()).emit()?;
        let n = f.u32("Copyright URL length").emit()?;
        f.ascii("Copyright URL", n.into()).emit()?;
    } else if g == COMPATIBILITY {
        f.u8("Profile").emit()?;
        f.u8("Mode").emit()?;
    } else if g == PADDING {
        let rest = f.remaining();
        f.node(
            Node::new("Padding")
                .span(f.peek_span(rest))
                .summary(format!("{rest} bytes")),
        );
        f.skip(rest);
    }
    Ok(())
}

fn stream_properties(f: &mut Fields<'_>) -> Result<()> {
    let kind = f.guid("Stream type").with(named_guid).emit()?;
    let ec = f.guid("Error correction type").with(named_guid).emit()?;
    f.u64("Time offset")
        .desc("100-ns units")
        .with(|&t, n| n.summary(vidutil::seconds_ms(t / 10_000)))
        .emit()?;
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
    // Each layout only where the type-specific data is large enough.
    if kind == AUDIO_MEDIA && ts_len >= 16 {
        wav::wave_format(f, &())?;
    } else if kind == VIDEO_MEDIA && ts_len >= 51 {
        f.u32("Encoded image width").emit()?;
        f.u32("Encoded image height").emit()?;
        f.u8("Reserved flags").emit()?;
        f.u16("Format data size").emit()?;
        bitmapinfoheader(f)?;
    } else if kind == JFIF_MEDIA && ts_len >= 12 {
        f.u32("Image width").emit()?;
        f.u32("Image height").emit()?;
        f.u32("Reserved").emit()?;
    } else if kind == BINARY_MEDIA && ts_len >= 64 {
        f.guid("Major media type").emit()?;
        f.guid("Media subtype").emit()?;
        f.u32("Fixed-size samples").emit()?;
        f.u32("Temporal compression").emit()?;
        f.u32("Sample size").emit()?;
        f.guid("Format type").emit()?;
        let n = f.u32("Format data size").emit()?;
        if n > 0 {
            f.bytes("Format data", n.into()).emit()?;
        }
    }
    if f.pos() < end {
        let n = end.saturating_sub(f.pos());
        f.bytes("Type-specific data", n).emit()?;
    }
    f.seek(end);
    if ec_len > 0 {
        if ec == AUDIO_SPREAD && ec_len >= 7 {
            let start = f.pos();
            f.u8("Span")
                .desc("Packets an audio frame is spread over")
                .emit()?;
            f.u16("Virtual packet length").emit()?;
            f.u16("Virtual chunk length").emit()?;
            let n = f.u16("Silence data length").emit()?;
            if n > 0 {
                f.bytes("Silence data", n.into()).emit()?;
            }
            f.seek(start.saturating_add(ec_len.into()));
        } else {
            f.bytes("Error correction data", ec_len.into()).emit()?;
        }
    }
    Ok(())
}

fn extended_stream(f: &mut Fields<'_>) -> Result<()> {
    f.u64("Start time")
        .with(|&t, n| n.summary(format!("{t} ms")))
        .emit()?;
    f.u64("End time")
        .with(|&t, n| n.summary(format!("{t} ms")))
        .emit()?;
    f.u32("Data bitrate")
        .with(|&b, n| n.summary(format!("{} kb/s", vidutil::num(f64::from(b) / 1000.0))))
        .emit()?;
    f.u32("Buffer size").desc("Milliseconds").emit()?;
    f.u32("Initial buffer fullness")
        .desc("Milliseconds")
        .emit()?;
    f.u32("Alternate data bitrate").emit()?;
    f.u32("Alternate buffer size").emit()?;
    f.u32("Alternate initial buffer fullness").emit()?;
    f.u32("Maximum object size").emit()?;
    f.u32("Flags").flags(EXT_STREAM_FLAGS).emit()?;
    f.u16("Stream number").emit()?;
    f.u16("Stream language ID index").emit()?;
    f.u64("Average time per frame")
        .desc("100-ns units")
        .with(|&t, n| {
            if t > 0 {
                n.summary(format!("{} fps", vidutil::num(10_000_000.0 / t as f64)))
            } else {
                n
            }
        })
        .emit()?;
    let names = f.u16("Stream name count").emit()?;
    let systems = f.u16("Payload extension system count").emit()?;
    for _ in 0..names {
        if f.remaining() < 4 {
            break;
        }
        f.u16("Language ID index").emit()?;
        let len = f.u16("Stream name length").emit()?;
        utf16_bytes(f, "Stream name", len.into())?;
    }
    for i in 0..systems {
        if f.remaining() < 22 {
            break;
        }
        group(
            f,
            format!("Payload extension system {}", i.saturating_add(1)),
            payload_extension_system,
        )?;
    }
    Ok(())
}

fn payload_extension_system(f: &mut Fields<'_>) -> Result<Option<String>> {
    let g = f.guid("Extension system ID").with(named_guid).emit()?;
    let size = f
        .u16("Extension data size")
        .desc("Bytes per payload; 0xffff = variable")
        .emit()?;
    let n = f.u32("Extension system info length").emit()?;
    if n > 0 {
        f.bytes("Extension system info", n.into()).emit()?;
    }
    let name = guid_name(&g)
        .map(|n| n.trim_start_matches("Payload Extension: ").to_owned())
        .unwrap_or_else(|| g.to_string());
    Ok(Some(if size == 0xffff {
        format!("{name}, variable size")
    } else {
        format!("{name}, {size} bytes")
    }))
}

fn codec_entry(f: &mut Fields<'_>) -> Result<Option<String>> {
    let kind = f.u16("Type").enumeration(CODEC_TYPES).emit()?;
    let len = f.u16("Codec name length").desc("In characters").emit()?;
    let name = f.utf16("Codec name", len.into()).emit()?;
    let len = f
        .u16("Codec description length")
        .desc("In characters")
        .emit()?;
    let description = f.utf16("Codec description", len.into()).emit()?;
    let len = f.u16("Codec information length").emit()?;
    let at = f.pos();
    let info = f.bytes("Codec information", len.into()).get()?;
    let span = f.block().span.sub(at, len.into());
    let mut node = Node::new("Codec information")
        .span(span)
        .value(Value::Bytes(info.clone()));
    if kind == 1 && info.len() == 4 {
        node = node.summary(compression_name(&info));
    } else if kind == 2
        && let Some(tag) = u16_le(&info, 0)
    {
        // Only the format tag: the codec list carries no WAVEFORMATEX.
        node = node.summary(wav::tag_name(tag));
    }
    f.node(node);
    let what = crate::value::lookup(CODEC_TYPES, kind.into()).unwrap_or("codec");
    let mut s = format!("{what}: {}", name.trim_end_matches('\0'));
    let description = description.trim_end_matches('\0');
    if !description.is_empty() {
        s.push_str(&format!(" ({description})"));
    }
    Ok(Some(s))
}

fn marker(f: &mut Fields<'_>) -> Result<Option<String>> {
    f.u64("Offset")
        .hex()
        .desc("Byte offset of the marker within the data packets")
        .emit()?;
    let time = f
        .u64("Presentation time")
        .desc("100-ns units, preroll included")
        .with(|&t, n| n.summary(vidutil::seconds_ms(t / 10_000)))
        .emit()?;
    f.u16("Entry length").emit()?;
    f.u32("Send time")
        .with(|&t, n| n.summary(format!("{t} ms")))
        .emit()?;
    f.u32("Flags").hex().emit()?;
    let len = f
        .u32("Marker description length")
        .desc("In characters")
        .emit()?;
    let name = f.utf16("Marker description", len.into()).emit()?;
    Ok(Some(format!(
        "{} \"{}\"",
        vidutil::seconds_ms(time / 10_000),
        name.trim_end_matches('\0')
    )))
}

fn script_command(f: &mut Fields<'_>) -> Result<Option<String>> {
    let time = f
        .u32("Presentation time")
        .with(|&t, n| n.summary(vidutil::seconds_ms(t.into())))
        .emit()?;
    f.u16("Type index").emit()?;
    let len = f.u16("Command name length").desc("In characters").emit()?;
    let name = f.utf16("Command name", len.into()).emit()?;
    Ok(Some(format!(
        "{} {}",
        vidutil::seconds_ms(time.into()),
        name.trim_end_matches('\0')
    )))
}

/// An Extended Content Description descriptor or a Metadata (Library)
/// description record: a node named after the attribute, with its value.
fn attribute(f: &mut Fields<'_>, obj: &Object, record: bool) -> Result<()> {
    let start = f.pos();
    let (name, kind, len, stream, language) = if record {
        let language = f.u16("Language list index").get()?;
        let stream = f.u16("Stream number").get()?;
        let name_len = f.u16("Name length").get()?;
        let kind = f.u16("Data type").get()?;
        let len = f.u32("Data length").get()?;
        let name = f.utf16("Name", u64::from(name_len / 2)).get()?;
        if name_len & 1 == 1 {
            f.skip(1);
        }
        (name, kind, u64::from(len), stream, language)
    } else {
        let name_len = f.u16("Name length").get()?;
        let name = f.utf16("Name", u64::from(name_len / 2)).get()?;
        if name_len & 1 == 1 {
            f.skip(1);
        }
        let kind = f.u16("Value type").get()?;
        let len = f.u16("Value length").get()?;
        (name, kind, u64::from(len), 0, 0)
    };
    let value_at = f.pos();
    let bytes = f.bytes("Value", len).get()?;
    let span = f.block().span.sub(start, f.pos().saturating_sub(start));
    let value_span = f.block().span.sub(value_at, len);
    let mut node = Node::new(name.clone())
        .span(span)
        .lazy(expand_attribute, (span, record));
    if name == "WM/Picture" && kind == 1 {
        node = node.summary(picture_summary(&bytes).unwrap_or_else(|| format!("{len} bytes")));
        node = node.lazy(
            expand_picture,
            (
                obj.input,
                span,
                value_span.offset.saturating_sub(span.offset),
                record,
            ),
        );
    } else {
        match typed_value(kind, &bytes) {
            Some(v) => node = node.value(v),
            None => {
                node = node.summary(format!(
                    "{len} bytes ({})",
                    vidutil::lookup_or(VALUE_TYPES, kind.into())
                ));
            }
        }
    }
    let mut notes = Vec::new();
    if stream != 0 {
        notes.push(format!("stream {stream}"));
    }
    if language != 0 {
        notes.push(format!("language {language}"));
    }
    if !notes.is_empty() {
        let s = notes.join(", ");
        node = match node.summary.take() {
            Some(old) => node.summary(format!("{old}; {s}")),
            None => node.summary(s),
        };
    }
    f.node(node);
    Ok(())
}

/// The fields of an attribute.
async fn expand_attribute(cx: Cx, (span, record): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    attribute_fields(&mut f, record)?;
    Ok(())
}

/// Emits an attribute's header; returns its data type and length.
fn attribute_fields(f: &mut Fields<'_>, record: bool) -> Result<(u16, u64)> {
    if record {
        f.u16("Language list index").emit()?;
        f.u16("Stream number").desc("0 = the whole file").emit()?;
        let name_len = f.u16("Name length").emit()?;
        let kind = f.u16("Data type").enumeration(VALUE_TYPES).emit()?;
        let len = f.u32("Data length").emit()?;
        utf16_bytes(f, "Name", name_len.into())?;
        let bytes = f.bytes("Data", len.into()).get()?;
        emit_value(f, kind, &bytes, len.into());
        Ok((kind, len.into()))
    } else {
        let name_len = f.u16("Name length").emit()?;
        utf16_bytes(f, "Name", name_len.into())?;
        let kind = f.u16("Value type").enumeration(VALUE_TYPES).emit()?;
        let len = f.u16("Value length").emit()?;
        let bytes = f.bytes("Value", len.into()).get()?;
        emit_value(f, kind, &bytes, len.into());
        Ok((kind, len.into()))
    }
}

fn emit_value(f: &mut Fields<'_>, kind: u16, bytes: &[u8], len: u64) {
    let span = f.peek_span(0);
    let span = Span::new(span.source, span.offset.saturating_sub(len), len);
    let node = Node::new("Value").span(span);
    f.node(match typed_value(kind, bytes) {
        Some(v) => node.value(v),
        None => node.summary(format!("{len} bytes")),
    });
}

/// A typed attribute value; `None` for large byte arrays.
fn typed_value(kind: u16, bytes: &[u8]) -> Option<Value> {
    Some(match kind {
        0 => Value::Text(
            crate::text::utf16(bytes, LE)
                .trim_end_matches('\0')
                .to_owned(),
        ),
        2 => Value::Bool(bytes.iter().any(|&b| b != 0)),
        3..=5 => Value::UInt {
            value: bytes
                .iter()
                .take(8)
                .rev()
                .fold(0u64, |a, &b| (a << 8) | u64::from(b)),
            bits: u8::try_from(bytes.len().saturating_mul(8).min(64)).unwrap_or(64),
            radix: Radix::Dec,
        },
        6 if bytes.len() == 16 => Value::Guid(read_guid(bytes, 0)?),
        _ if bytes.len() <= 32 => Value::Bytes(bytes.to_vec()),
        _ => return None,
    })
}

/// "front cover, image/jpeg, 12345 bytes".
fn picture_summary(d: &[u8]) -> Option<String> {
    let kind = *d.first()?;
    let len = u32_le(d, 1)?;
    let (mime, _, _) = crate::text::utf16z(d.get(5..)?, LE);
    Some(format!(
        "{}, {mime}, {len} bytes",
        name_or(PICTURE_TYPE, kind.into(), "picture type")
    ))
}

/// WM/Picture: picture type, size, MIME type, description, image.
async fn expand_picture(
    cx: Cx,
    (input, span, value_at, record): (Input, Span, u64, bool),
) -> Result<()> {
    let block = cx.block(span.sub(0, value_at)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    if record {
        f.u16("Language list index").emit()?;
        f.u16("Stream number").emit()?;
        let name_len = f.u16("Name length").emit()?;
        f.u16("Data type").enumeration(VALUE_TYPES).emit()?;
        f.u32("Data length").emit()?;
        utf16_bytes(&mut f, "Name", name_len.into())?;
    } else {
        let name_len = f.u16("Name length").emit()?;
        utf16_bytes(&mut f, "Name", name_len.into())?;
        f.u16("Value type").enumeration(VALUE_TYPES).emit()?;
        f.u16("Value length").emit()?;
    }
    let value = span.tail(value_at);
    let head = cx.block(value.sub(0, 0x1000)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u8("Picture type").enumeration(PICTURE_TYPE).emit()?;
    let len = f.u32("Picture data length").emit()?;
    f.utf16z("MIME type").emit()?;
    f.utf16z("Description").emit()?;
    let at = f.pos();
    cx.emit(embedded("Picture", input.nested(value.sub(at, len.into()))));
    Ok(())
}

// ---------------------------------------------------------------------------
// Index objects

/// Simple Index, Index and Media Object Index objects.
async fn index_object(cx: &Cx, obj: &Object, body: Span) -> Result<()> {
    let b = cx.block(body.sub(0, 0x1000)).await?;
    let mut f = Fields::emitting(cx, &b, LE);
    let packet_size = u64::from(obj.packet_size);
    if obj.guid == SIMPLE_INDEX {
        f.guid("File ID").emit()?;
        f.u64("Index entry time interval")
            .desc("100-ns units")
            .with(|&t, n| n.summary(vidutil::seconds_ms(t / 10_000)))
            .emit()?;
        f.u32("Maximum packet count").emit()?;
        let n = f.u32("Index entries count").emit()?;
        let table = body.sub(f.pos(), u64::from(n).saturating_mul(6));
        cx.emit(
            Node::new("Index entries")
                .span(table)
                .summary(entry_count(n.into()))
                .lazy(simple_index_entries, (table, obj.packets, packet_size)),
        );
        return Ok(());
    }
    let interval = f
        .u32("Index entry time interval")
        .with(|&v, n| n.summary(format!("{v} ms")))
        .emit()?;
    let specifiers = f.u16("Index specifiers count").emit()?;
    let blocks = f.u32("Index blocks count").emit()?;
    for _ in 0..specifiers {
        if f.remaining() < 4 {
            break;
        }
        f.u16("Stream number").emit()?;
        f.u16("Index type").enumeration(INDEX_TYPES).emit()?;
    }
    // Blocks: entry count, a base position per specifier, then entries of
    // one offset per specifier.
    let mut pos = f.pos();
    let width = u64::from(specifiers).saturating_mul(4);
    for i in 0..blocks.min(1024) {
        let head = cx.read_avail(body.sub(pos, 4)).await?;
        let Some(count) = u32_le(&head, 0) else {
            break;
        };
        let len = 4u64
            .saturating_add(u64::from(specifiers).saturating_mul(8))
            .saturating_add(u64::from(count).saturating_mul(width));
        let span = body.sub(pos, len);
        cx.emit(
            Node::new(format!("Index block {}", i.saturating_add(1)))
                .span(span)
                .summary(format!(
                    "{}, every {interval} ms",
                    entry_count(count.into())
                ))
                .lazy(index_block, (span, specifiers, count, obj.packets)),
        );
        pos = pos.saturating_add(len);
        cx.checkpoint().await;
    }
    Ok(())
}

async fn simple_index_entries(
    cx: Cx,
    (table, packets, size): (Span, Option<Span>, u64),
) -> Result<()> {
    let count = table.len / 6;
    cx.set_count(Count::Exact(count));
    let mut i = 0u64;
    while i < count {
        let n = count.saturating_sub(i).min(256);
        let page = table.sub(i.saturating_mul(6), n.saturating_mul(6));
        let d = cx.read_avail(page).await?;
        for j in 0..n {
            let at = vidutil::us(j.saturating_mul(6));
            let number = u32_le(&d, at).unwrap_or(0);
            let packets_n = u16_le(&d, at.saturating_add(4)).unwrap_or(0);
            let span = page.sub(j.saturating_mul(6), 6);
            let mut node = Node::new(format!("Entry {}", i.saturating_add(j)))
                .span(span)
                .summary(format!("packet {number}, {}", plural(packets_n, "packet")))
                .lazy(simple_entry, span);
            if let Some(p) = packets {
                node = node.target(p.sub(
                    u64::from(number).saturating_mul(size),
                    u64::from(packets_n.max(1)).saturating_mul(size),
                ));
            }
            cx.push(node).await;
        }
        i = i.saturating_add(n);
    }
    Ok(())
}

async fn simple_entry(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Packet number").emit()?;
    f.u16("Packet count").emit()?;
    Ok(())
}

async fn index_block(
    cx: Cx,
    (span, specifiers, count, packets): (Span, u16, u32, Option<Span>),
) -> Result<()> {
    let head_len = 4u64.saturating_add(u64::from(specifiers).saturating_mul(8));
    let block = cx.block(span.sub(0, head_len)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Index entry count").emit()?;
    let mut bases = Vec::new();
    for _ in 0..specifiers {
        bases.push(f.u64("Block position").hex().emit()?);
    }
    let width = u64::from(specifiers).saturating_mul(4).max(1);
    let entries = span.tail(head_len);
    let count = u64::from(count).min(entries.len.checked_div(width).unwrap_or(0));
    let mut i = 0u64;
    while i < count {
        let n = count.saturating_sub(i).min(256);
        let page = entries.sub(i.saturating_mul(width), n.saturating_mul(width));
        let d = cx.read_avail(page).await?;
        for j in 0..n {
            let at = vidutil::us(j.saturating_mul(width));
            let offsets: Vec<u32> = (0..usize::from(specifiers))
                .filter_map(|k| u32_le(&d, at.saturating_add(k.saturating_mul(4))))
                .collect();
            let mut node = Node::new(format!("Entry {}", i.saturating_add(j)))
                .span(page.sub(j.saturating_mul(width), width))
                .summary(
                    offsets
                        .iter()
                        .map(|o| format!("{o:#x}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            if let (Some(p), Some(o), Some(base)) = (packets, offsets.first(), bases.first()) {
                node = node.target(p.sub(base.saturating_add(u64::from(*o)), 1));
            }
            cx.push(node).await;
        }
        i = i.saturating_add(n);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Codec structures shared with AVI and Matroska

/// "Motion JPEG (MJPG)", "BI_RGB".
pub fn compression_name(c: &[u8]) -> String {
    let v = u32_le(c, 0).unwrap_or(0);
    if v < 0x100 {
        return match v {
            0 => "RGB".to_owned(),
            _ => vidutil::lookup_or(bmp::COMPRESSION, v.into()),
        };
    }
    let code = vidutil::fourcc(c);
    match vidutil::codec_name(c) {
        Some(name) => format!("{name} ({})", code.trim_end()),
        None => code,
    }
}

/// BITMAPINFOHEADER, as used by ASF, AVI and Matroska (V_MS/VFW/FOURCC)
/// video streams, with the codec data within `biSize` and the palette.
pub fn bitmapinfoheader(f: &mut Fields<'_>) -> Result<()> {
    let start = f.pos();
    let info = bmp::info_header(f, &bmp::Compression::FourCC)?;
    let (size, bits, used, raw) = (
        info.size,
        info.bit_count,
        info.colors_used,
        info.compression,
    );
    let end = start.saturating_add(size.into());
    if end > f.pos() {
        let n = end.saturating_sub(f.pos());
        f.bytes("Codec-specific data", n).emit()?;
    }
    f.seek(end.max(f.pos()));
    if bits <= 8 && bits > 0 && raw <= 2 && f.remaining() >= 4 {
        let colors = if used == 0 {
            1u64 << bits.min(8)
        } else {
            u64::from(used).min(256)
        };
        let len = colors.saturating_mul(4).min(f.remaining());
        let span = f.peek_span(len);
        f.node(
            Node::new("Palette")
                .span(span)
                .summary(plural(len / 4, "colour"))
                .desc("RGBQUAD entries: blue, green, red, reserved"),
        );
        f.skip(len);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Data packets

const PAGE: u64 = 64;

async fn expand_packets(cx: Cx, (span, declared, size): (Span, u64, u32)) -> Result<()> {
    let size = u64::from(size);
    if size == 0 {
        cx.emit(Node::new("Packet data").span(span));
        return Ok(());
    }
    let fits = span.len.checked_div(size).unwrap_or(0);
    let count = if declared == 0 {
        fits
    } else {
        fits.min(declared)
    };
    cx.set_count(Count::Exact(count));
    let mut i = 0u64;
    while i < count {
        let n = count.saturating_sub(i).min(PAGE);
        let page = span.sub(i.saturating_mul(size), n.saturating_mul(size));
        let data = cx.read_avail(page).await?;
        for j in 0..n {
            let at = vidutil::us(j.saturating_mul(size));
            let p = data
                .get(at..at.saturating_add(vidutil::us(size)))
                .unwrap_or_default();
            let pspan = page.sub(j.saturating_mul(size), size);
            let mut node = Node::new(format!("Packet {}", i.saturating_add(j)))
                .span(pspan)
                .lazy(expand_packet, pspan);
            let block = Block {
                span: pspan,
                data: p.to_vec(),
            };
            match parse_packet(&mut Fields::new(&block, LE)) {
                Ok(pk) => node = node.summary(pk.summary()),
                Err(e) => node = node.diag(e),
            }
            cx.push(node).await;
        }
        i = i.saturating_add(n);
        cx.checkpoint().await;
    }
    let rest = span.tail(count.saturating_mul(size));
    if !rest.is_empty() {
        cx.emit(Node::new("Trailing data").span(rest));
    }
    Ok(())
}

const LENGTH_TYPE_FLAGS: FlagTable = &[
    flag(0x01, "MULTIPLE_PAYLOADS"),
    field(0x06, 0x02, "SEQUENCE_BYTE"),
    field(0x06, 0x04, "SEQUENCE_WORD"),
    field(0x06, 0x06, "SEQUENCE_DWORD"),
    field(0x18, 0x08, "PADDING_BYTE"),
    field(0x18, 0x10, "PADDING_WORD"),
    field(0x18, 0x18, "PADDING_DWORD"),
    field(0x60, 0x20, "PACKET_LENGTH_BYTE"),
    field(0x60, 0x40, "PACKET_LENGTH_WORD"),
    field(0x60, 0x60, "PACKET_LENGTH_DWORD"),
    flag(0x80, "ERROR_CORRECTION"),
];

const PROPERTY_FLAGS: FlagTable = &[
    field(0x03, 0x01, "REPLICATED_LENGTH_BYTE"),
    field(0x03, 0x02, "REPLICATED_LENGTH_WORD"),
    field(0x03, 0x03, "REPLICATED_LENGTH_DWORD"),
    field(0x0c, 0x04, "OFFSET_BYTE"),
    field(0x0c, 0x08, "OFFSET_WORD"),
    field(0x0c, 0x0c, "OFFSET_DWORD"),
    field(0x30, 0x10, "OBJECT_NUMBER_BYTE"),
    field(0x30, 0x20, "OBJECT_NUMBER_WORD"),
    field(0x30, 0x30, "OBJECT_NUMBER_DWORD"),
    field(0xc0, 0x40, "STREAM_NUMBER_BYTE"),
    field(0xc0, 0x80, "STREAM_NUMBER_WORD"),
    field(0xc0, 0xc0, "STREAM_NUMBER_DWORD"),
];

/// A field of 0, 1, 2 or 4 bytes, by a 2-bit length type.
fn sized(f: &mut Fields<'_>, name: &'static str, kind: u8) -> Result<u64> {
    match kind & 3 {
        1 => f.u8(name).emit().map(u64::from),
        2 => f.u16(name).emit().map(u64::from),
        3 => f.u32(name).emit().map(u64::from),
        _ => Ok(0),
    }
}

/// What a packet's parsing information says.
struct Packet {
    multiple: bool,
    /// Property flags (the length types of the payload header fields).
    props: u8,
    /// Length type of the payload lengths (multiple payloads).
    payload_length_type: u8,
    send_time: u32,
    duration: u16,
    padding: u64,
    /// Explicit packet length, if coded.
    length: Option<u64>,
    /// Where the payloads start, relative to the packet.
    payloads: u64,
    count: u8,
}

impl Packet {
    fn summary(&self) -> String {
        let mut s = format!(
            "send time {} ms, duration {} ms",
            self.send_time, self.duration
        );
        if self.multiple {
            s.push_str(&format!(", {}", plural(self.count, "payload")));
        } else {
            s.push_str(", 1 payload");
        }
        if self.padding > 0 {
            s.push_str(&format!(", {} bytes of padding", self.padding));
        }
        s
    }
}

/// The error correction data and payload parsing information.
fn parse_packet(f: &mut Fields<'_>) -> Result<Packet> {
    let first = f.u8("Error correction flags").get()?;
    f.seek(0);
    if first & 0x80 != 0 {
        f.u8("Error correction flags")
            .hex()
            .desc("Bit 7: present; bit 4: opaque data; bits 0-3: data length")
            .with(|&v, n| n.summary(format!("{} bytes of error correction data", v & 0x0f)))
            .emit()?;
        let n = first & 0x0f;
        if n > 0 {
            f.bytes("Error correction data", n.into()).emit()?;
        }
    }
    let ltf = f.u8("Length type flags").flags(LENGTH_TYPE_FLAGS).emit()?;
    let props = f.u8("Property flags").flags(PROPERTY_FLAGS).emit()?;
    let length = match (ltf >> 5) & 3 {
        0 => None,
        t => Some(sized(f, "Packet length", t)?),
    };
    sized(f, "Sequence", ltf >> 1)?;
    let padding = sized(f, "Padding length", ltf >> 3)?;
    let send_time = f
        .u32("Send time")
        .with(|&t, n| n.summary(format!("{t} ms")))
        .emit()?;
    let duration = f
        .u16("Duration")
        .with(|&t, n| n.summary(format!("{t} ms")))
        .emit()?;
    let multiple = ltf & 1 != 0;
    let (payload_length_type, count) = if multiple {
        let pf = f
            .u8("Payload flags")
            .hex()
            .with(|&v, n| {
                n.summary(format!(
                    "{}, lengths: {}",
                    plural(v & 0x3f, "payload"),
                    ["none", "byte", "word", "dword"]
                        .get(usize::from(v >> 6))
                        .copied()
                        .unwrap_or("?")
                ))
            })
            .emit()?;
        (pf >> 6, pf & 0x3f)
    } else {
        (0, 1)
    };
    Ok(Packet {
        multiple,
        props,
        payload_length_type,
        send_time,
        duration,
        padding,
        length,
        payloads: f.pos(),
        count,
    })
}

/// What a payload header says.
struct PayloadHead {
    stream: u8,
    object: u64,
    offset: u64,
    replicated: u64,
    /// Media object size and presentation time from the replicated data.
    object_size: Option<u32>,
    time: Option<u32>,
    /// Payload length (multiple payloads only).
    length: Option<u64>,
}

/// One payload's header (from the stream number to the payload length).
fn payload_header(f: &mut Fields<'_>, props: u8, length_type: Option<u8>) -> Result<PayloadHead> {
    let stream = f
        .u8("Stream number")
        .with(|&v, n| {
            n.summary(format!(
                "stream {}{}",
                v & 0x7f,
                if v & 0x80 != 0 { ", keyframe" } else { "" }
            ))
        })
        .emit()?;
    let object = sized(f, "Media object number", props >> 4)?;
    let offset = sized(f, "Offset into media object", props >> 2)?;
    let replicated = sized(f, "Replicated data length", props)?;
    let mut object_size = None;
    let mut time = None;
    if replicated == 1 {
        f.u8("Presentation time delta")
            .desc("Compressed payload: the offset field holds the presentation time")
            .emit()?;
        time = u32::try_from(offset).ok();
    } else if replicated >= 8 {
        object_size = Some(f.u32("Media object size").emit()?);
        time = Some(
            f.u32("Presentation time")
                .with(|&t, n| n.summary(format!("{t} ms")))
                .emit()?,
        );
        if replicated > 8 {
            f.bytes("Payload extension data", replicated.saturating_sub(8))
                .emit()?;
        }
    } else if replicated > 0 {
        f.bytes("Replicated data", replicated).emit()?;
    }
    let length = match length_type {
        Some(t) => Some(sized(f, "Payload length", t)?),
        None => None,
    };
    Ok(PayloadHead {
        stream,
        object,
        offset,
        replicated,
        object_size,
        time,
        length,
    })
}

impl PayloadHead {
    fn compressed(&self) -> bool {
        self.replicated == 1
    }

    fn summary(&self, data_len: u64) -> String {
        let mut s = format!("stream {}", self.stream & 0x7f);
        if self.stream & 0x80 != 0 {
            s.push_str(", keyframe");
        }
        if self.compressed() {
            s.push_str(", compressed");
        } else {
            s.push_str(&format!(", object {}", self.object));
            if self.offset > 0 || self.object_size.is_some_and(|z| u64::from(z) != data_len) {
                s.push_str(&format!(" at +{}", self.offset));
            }
        }
        if let Some(t) = self.time {
            s.push_str(&format!(", {t} ms"));
        }
        s.push_str(&format!(", {data_len} bytes"));
        s
    }
}

async fn expand_packet(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 0x100000)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let pk = parse_packet(&mut f)?;
    let end = pk
        .length
        .unwrap_or(span.len)
        .min(span.len)
        .saturating_sub(pk.padding);
    let mut pos = pk.payloads;
    let mut silent = Fields::new(&block, LE);
    let length_type = pk.multiple.then_some(pk.payload_length_type);
    for i in 0..pk.count {
        if pos >= end {
            break;
        }
        silent.seek(pos);
        let head = match payload_header(&mut silent, pk.props, length_type) {
            Ok(h) => h,
            Err(e) => {
                cx.emit(
                    Node::new("Invalid payload")
                        .span(span.sub(pos, end.saturating_sub(pos)))
                        .diag(e),
                );
                break;
            }
        };
        let header_len = silent.pos().saturating_sub(pos);
        let data_len = head
            .length
            .unwrap_or_else(|| end.saturating_sub(silent.pos()));
        let total = header_len.saturating_add(data_len);
        let pspan = span.sub(pos, total);
        let mut node = Node::new(format!("Payload {}", u16::from(i).saturating_add(1)))
            .span(pspan)
            .summary(head.summary(data_len))
            .lazy(
                expand_payload,
                PayloadState {
                    span: pspan,
                    props: pk.props,
                    length_type,
                },
            );
        if pos.saturating_add(total) > end {
            node = node.diag(Diagnostic::malformed("payload runs past the packet"));
        }
        cx.emit(node);
        pos = pos.saturating_add(total.max(1));
    }
    if pk.padding > 0 {
        cx.emit(
            Node::new("Padding")
                .span(span.sub(end, pk.padding))
                .summary(format!("{} bytes", pk.padding)),
        );
    } else if pos < end {
        cx.emit(Node::new("Unused data").span(span.sub(pos, end.saturating_sub(pos))));
    }
    if end < span.len && pk.length.is_some() {
        let tail = end.saturating_add(pk.padding);
        if tail < span.len {
            cx.emit(Node::new("Unused data").span(span.tail(tail)));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct PayloadState {
    span: Span,
    props: u8,
    length_type: Option<u8>,
}

async fn expand_payload(cx: Cx, st: PayloadState) -> Result<()> {
    let block = cx.block(st.span.sub(0, 0x400)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let head = payload_header(&mut f, st.props, st.length_type)?;
    let data = st.span.tail(f.pos());
    if head.compressed() {
        // Sub-payloads: a size byte, then that many bytes, repeated.
        let d = cx.read_avail(data).await?;
        let mut at = 0usize;
        let mut index = 0u32;
        while let Some(&len) = d.get(at) {
            let span = data.sub(to_u64(at), 1u64.saturating_add(len.into()));
            index = index.saturating_add(1);
            cx.emit(
                Node::new(format!("Sub-payload {index}"))
                    .span(span)
                    .summary(format!("{len} bytes")),
            );
            at = at.saturating_add(1).saturating_add(usize::from(len));
        }
    } else {
        cx.emit(
            Node::new("Payload data")
                .span(data)
                .summary(format!("{} bytes", data.len)),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut packet_size = 0;
    if let Some((s, size)) = file_summary(&cx, input.span).await {
        cx.annotate(s);
        packet_size = size;
    }
    objects(&cx, input, input.span, 0, packet_size, None).await
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
    let mut markers = 0u32;
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
            if let Some(s) = stream_short(obj) {
                streams.push(s);
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
        } else if g == MARKER {
            markers = u32_le(obj, 40).unwrap_or(0);
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
    if let Some(d) = duration {
        parts.push(d);
    }
    if !streams.is_empty() {
        parts.push(streams.join(" + "));
    }
    if markers > 0 {
        parts.push(plural(markers, "marker"));
    }
    if let Some(t) = title {
        parts.push(format!("\"{t}\""));
    }
    Some((parts.join(", "), packet_size))
}
