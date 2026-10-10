//! OpenStreetMap PBF extracts: a sequence of blocks, each a 4-byte
//! big-endian length, a `BlobHeader` message and a `Blob` message whose
//! payload (raw or compressed) is an `OSMHeader` (`HeaderBlock`) or
//! `OSMData` (`PrimitiveBlock`) message. All of them are shown through the
//! shared protobuf walker with the schemas from `fileformat.proto` and
//! `osmformat.proto`.

use crate::bytes::u32_be;
use crate::codec::Codec;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::size;
use crate::formats::util::val::uint;
use crate::formats::util::wire::protobuf::{self as pb, Elem, LEN, Msg, Ty, VARINT, f};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

// ---------------------------------------------------------------------------
// Schemas

static BLOB_HEADER: Msg = Msg {
    name: "BlobHeader",
    fields: &[
        f(1, "type", Ty::Str),
        f(2, "indexdata", Ty::Bytes),
        f(3, "datasize", Ty::Int),
    ],
    title: &[1],
};

static BLOB: Msg = Msg {
    name: "Blob",
    fields: &[
        f(1, "raw", Ty::Bytes),
        f(2, "raw_size", Ty::Int),
        f(3, "zlib_data", Ty::Bytes),
        f(4, "lzma_data", Ty::Bytes),
        f(5, "OBSOLETE_bzip2_data", Ty::Bytes),
        f(6, "lz4_data", Ty::Bytes),
        f(7, "zstd_data", Ty::Bytes),
    ],
    title: &[],
};

static HEADER_BBOX: Msg = Msg {
    name: "HeaderBBox",
    fields: &[
        f(1, "left", Ty::SInt),
        f(2, "right", Ty::SInt),
        f(3, "top", Ty::SInt),
        f(4, "bottom", Ty::SInt),
    ],
    title: &[],
};

static HEADER_BLOCK: Msg = Msg {
    name: "HeaderBlock",
    fields: &[
        f(1, "bbox", Ty::Msg(&HEADER_BBOX)),
        f(4, "required_features", Ty::Str),
        f(5, "optional_features", Ty::Str),
        f(16, "writingprogram", Ty::Str),
        f(17, "source", Ty::Str),
        f(32, "osmosis_replication_timestamp", Ty::Int),
        f(33, "osmosis_replication_sequence_number", Ty::Int),
        f(34, "osmosis_replication_base_url", Ty::Str),
    ],
    title: &[16],
};

static STRING_TABLE: Msg = Msg {
    name: "StringTable",
    fields: &[f(1, "s", Ty::Str)],
    title: &[],
};

static INFO: Msg = Msg {
    name: "Info",
    fields: &[
        f(1, "version", Ty::Int),
        f(2, "timestamp", Ty::Int),
        f(3, "changeset", Ty::Int),
        f(4, "uid", Ty::Int),
        f(5, "user_sid", Ty::Int),
        f(6, "visible", Ty::Bool),
    ],
    title: &[],
};

// Packed `sint64` fields (delta-coded ids, coordinates and times) have no
// element type in the walker; they are shown as bytes.
static DENSE_INFO: Msg = Msg {
    name: "DenseInfo",
    fields: &[
        f(1, "version", Ty::Packed(Elem::Varint)),
        f(2, "timestamp", Ty::Bytes),
        f(3, "changeset", Ty::Bytes),
        f(4, "uid", Ty::Bytes),
        f(5, "user_sid", Ty::Bytes),
        f(6, "visible", Ty::Packed(Elem::Varint)),
    ],
    title: &[],
};

static NODE: Msg = Msg {
    name: "Node",
    fields: &[
        f(1, "id", Ty::SInt),
        f(2, "keys", Ty::Packed(Elem::Varint)),
        f(3, "vals", Ty::Packed(Elem::Varint)),
        f(4, "info", Ty::Msg(&INFO)),
        f(8, "lat", Ty::SInt),
        f(9, "lon", Ty::SInt),
    ],
    title: &[],
};

static DENSE_NODES: Msg = Msg {
    name: "DenseNodes",
    fields: &[
        f(1, "id", Ty::Bytes),
        f(5, "denseinfo", Ty::Msg(&DENSE_INFO)),
        f(8, "lat", Ty::Bytes),
        f(9, "lon", Ty::Bytes),
        f(10, "keys_vals", Ty::Packed(Elem::Varint)),
    ],
    title: &[],
};

static WAY: Msg = Msg {
    name: "Way",
    fields: &[
        f(1, "id", Ty::Int),
        f(2, "keys", Ty::Packed(Elem::Varint)),
        f(3, "vals", Ty::Packed(Elem::Varint)),
        f(4, "info", Ty::Msg(&INFO)),
        f(8, "refs", Ty::Bytes),
        f(9, "lat", Ty::Bytes),
        f(10, "lon", Ty::Bytes),
    ],
    title: &[],
};

static RELATION: Msg = Msg {
    name: "Relation",
    fields: &[
        f(1, "id", Ty::Int),
        f(2, "keys", Ty::Packed(Elem::Varint)),
        f(3, "vals", Ty::Packed(Elem::Varint)),
        f(4, "info", Ty::Msg(&INFO)),
        f(8, "roles_sid", Ty::Packed(Elem::Varint)),
        f(9, "memids", Ty::Bytes),
        f(10, "types", Ty::Packed(Elem::Varint)),
    ],
    title: &[],
};

static CHANGESET: Msg = Msg {
    name: "ChangeSet",
    fields: &[f(1, "id", Ty::Int)],
    title: &[],
};

static PRIMITIVE_GROUP: Msg = Msg {
    name: "PrimitiveGroup",
    fields: &[
        f(1, "nodes", Ty::Msg(&NODE)),
        f(2, "dense", Ty::Msg(&DENSE_NODES)),
        f(3, "ways", Ty::Msg(&WAY)),
        f(4, "relations", Ty::Msg(&RELATION)),
        f(5, "changesets", Ty::Msg(&CHANGESET)),
    ],
    title: &[],
};

static PRIMITIVE_BLOCK: Msg = Msg {
    name: "PrimitiveBlock",
    fields: &[
        f(1, "stringtable", Ty::Msg(&STRING_TABLE)),
        f(2, "primitivegroup", Ty::Msg(&PRIMITIVE_GROUP)),
        f(17, "granularity", Ty::Int),
        f(18, "date_granularity", Ty::Int),
        f(19, "lat_offset", Ty::Int),
        f(20, "lon_offset", Ty::Int),
    ],
    title: &[],
};

/// The format's limits: a `BlobHeader` under 64 KiB, a `Blob` under
/// 32 MiB (raw or compressed).
const MAX_HEADER: u64 = 64 * 1024;
const MAX_BLOB: u64 = 32 << 20;

// ---------------------------------------------------------------------------
// OpenStreetMap PBF

fn osm_probe(h: &Head<'_>) -> bool {
    h.at(4, b"\x0a\x09OSMHeader")
}

declare_format!(pub OSM_PBF = "osm-pbf", "OpenStreetMap PBF", ["pbf", "osm.pbf"], "application/x-osm-pbf",
    Probe::Custom(osm_probe), osm_pbf);

/// Where a block is: its start, `BlobHeader` length and `Blob` length.
type Block = (Input, u64, u64, u64);

async fn osm_pbf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut blocks = 0u32;
    while pos.saturating_add(4) <= file.len {
        cx.progress_in(file, file.offset.saturating_add(pos));
        let len = u64::from(u32_be(&cx.read(file.sub(pos, 4)).await?, 0).unwrap_or(0));
        if len == 0 || len > MAX_HEADER {
            return Err(Diagnostic::malformed("implausible BlobHeader length").at(file.sub(pos, 4)));
        }
        let header = cx.read(file.sub(pos.saturating_add(4), len)).await?;
        let kind = pb::string_in(&header, 1).unwrap_or_default();
        let blob_len = pb::varint_in(&header, 3).unwrap_or(0);
        let total = 4u64.saturating_add(len).saturating_add(blob_len);
        blocks = blocks.saturating_add(1);
        cx.push(
            Node::new(kind)
                .span(file.sub(pos, total))
                .summary(size(blob_len))
                .lazy(osm_block, (input, pos, len, blob_len)),
        )
        .await;
        pos = pos.saturating_add(total);
    }
    cx.annotate(format!("OSM PBF, {blocks} blocks"));
    Ok(())
}

/// A block: its length prefix, `BlobHeader` and `Blob`, then the payload.
async fn osm_block(cx: Cx, (input, pos, len, blob_len): Block) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Header length")
            .span(file.sub(pos, 4))
            .value(uint(len, 32)),
    );
    let header = file.sub(pos.saturating_add(4), len);
    cx.emit(pb::node("BlobHeader", header, &BLOB_HEADER));
    let blob = file.sub(pos.saturating_add(4).saturating_add(len), blob_len);
    if blob.len < blob_len {
        cx.diag(Diagnostic::truncated(blob, blob.len));
    }
    cx.emit(pb::node("Blob", blob, &BLOB));
    let kind = pb::string_in(&cx.read(header).await?, 1).unwrap_or_default();
    let schema = match kind.as_str() {
        "OSMHeader" => &HEADER_BLOCK,
        "OSMData" => &PRIMITIVE_BLOCK,
        _ => return Ok(()),
    };
    if blob.len > MAX_BLOB {
        return Err(Diagnostic::limit("Blob larger than 32 MiB").at(blob));
    }
    let fields = pb::scan(&cx, blob, 16).await?;
    let raw_size = fields
        .iter()
        .find(|r| r.num == 2 && r.wire == VARINT)
        .map(|r| r.value);
    let Some(data) = fields
        .iter()
        .find(|r| r.wire == LEN && matches!(r.num, 1 | 3..=7))
    else {
        return Err(Diagnostic::malformed("Blob without data").at(blob));
    };
    let span = blob.sub(data.at, data.len);
    let codec = match data.num {
        1 => Codec::Stored,
        3 => Codec::Zlib,
        // The LZMA SDK's ".lzma" container.
        4 => Codec::LzmaAlone,
        7 => Codec::Zstd,
        _ => {
            let what = if data.num == 5 { "bzip2" } else { "LZ4" };
            cx.emit(
                Node::new(schema.name)
                    .span(span)
                    .diag(Diagnostic::unsupported(format!("{what}-compressed blobs"))),
            );
            return Ok(());
        }
    };
    let summary = match (&codec, raw_size) {
        (Codec::Stored, _) => size(span.len),
        (_, Some(n)) => format!("{} → {}", size(span.len), size(n)),
        (_, None) => format!("{} compressed", size(span.len)),
    };
    cx.emit(
        Node::new(schema.name)
            .span(span)
            .summary(summary)
            .lazy(osm_payload, (span, codec, raw_size, schema)),
    );
    Ok(())
}

/// A block's payload, decompressed if need be, walked with its schema.
async fn osm_payload(
    cx: Cx,
    (span, codec, raw_size, schema): (Span, Codec, Option<u64>, &'static Msg),
) -> Result<()> {
    let span = match codec {
        Codec::Stored => span,
        codec => {
            if raw_size.is_some_and(|n| n > MAX_BLOB) {
                return Err(Diagnostic::limit("raw_size larger than 32 MiB").at(span));
            }
            let decoded = crate::codec::decode_span(&cx, span, &codec, raw_size).await?;
            cx.annotate(format!("{:#x} bytes {}", decoded.span.len, codec.verb()));
            if let Some(e) = decoded.error {
                cx.diag(e);
            }
            decoded.span
        }
    };
    if span.len == 0 {
        return Ok(());
    }
    pb::message(cx, (span, schema, 0)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_name_their_fields_once() {
        for msg in [
            &BLOB_HEADER,
            &BLOB,
            &HEADER_BLOCK,
            &PRIMITIVE_BLOCK,
            &DENSE_NODES,
        ] {
            let mut nums: Vec<u64> = msg.fields.iter().map(|f| f.num).collect();
            nums.sort_unstable();
            nums.dedup();
            assert_eq!(nums.len(), msg.fields.len(), "{}", msg.name);
        }
    }
}
