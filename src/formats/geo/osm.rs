//! OpenStreetMap PBF extracts.

use crate::bytes::{to_u64, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::wire::protobuf::varint;
use crate::formats::{Codec, Head, Input, Probe, content};

// ---------------------------------------------------------------------------
// OpenStreetMap PBF

fn osm_probe(h: &Head<'_>) -> bool {
    h.at(4, b"\x0a\x09OSMHeader")
}

declare_format!(pub OSM_PBF = "osm-pbf", "OpenStreetMap PBF", ["pbf", "osm.pbf"], "application/x-osm-pbf",
    Probe::Custom(osm_probe), osm_pbf);

async fn osm_pbf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut blocks = 0u32;
    while pos.saturating_add(4) <= file.len {
        let len = u64::from(u32_be(&cx.read(file.sub(pos, 4)).await?, 0).unwrap_or(0));
        if len == 0 || len > 64 * 1024 {
            return Err(Diagnostic::malformed("implausible BlobHeader length").at(file.sub(pos, 4)));
        }
        let header = cx.read(file.sub(pos.saturating_add(4), len)).await?;
        // BlobHeader: 1 = type (string), 3 = datasize (varint).
        let mut at = 0usize;
        let mut kind = String::new();
        let mut size = 0u64;
        while at < header.len() {
            let Some(key) = varint(&header, &mut at) else {
                break;
            };
            match key {
                0x0a => {
                    let n = crate::bytes::to_usize(varint(&header, &mut at).unwrap_or(0));
                    kind = String::from_utf8_lossy(
                        header.get(at..at.saturating_add(n)).unwrap_or_default(),
                    )
                    .into_owned();
                    at = at.saturating_add(n);
                }
                0x18 => size = varint(&header, &mut at).unwrap_or(0),
                _ => {
                    let n = crate::bytes::to_usize(varint(&header, &mut at).unwrap_or(0));
                    at = at.saturating_add(n);
                }
            }
        }
        let blob = file.sub(pos.saturating_add(4).saturating_add(len), size);
        // Blob: 1 = raw, 2 = raw_size, 3 = zlib_data.
        let b = cx.read_avail(blob.sub(0, 16)).await?;
        let mut bat = 0usize;
        let mut node = crate::node::Node::new(kind.clone())
            .span(file.sub(pos, 4u64.saturating_add(len).saturating_add(size)));
        let mut raw_size = None;
        while bat < b.len() {
            let Some(key) = varint(&b, &mut bat) else {
                break;
            };
            match key {
                0x10 => raw_size = varint(&b, &mut bat),
                0x1a => {
                    let n = varint(&b, &mut bat).unwrap_or(0);
                    let data = blob.sub(to_u64(bat), n);
                    node = content(kind.clone(), input, data, Codec::Zlib, raw_size)
                        .span(file.sub(pos, 4u64.saturating_add(len).saturating_add(size)));
                    break;
                }
                _ => break,
            }
        }
        blocks = blocks.saturating_add(1);
        cx.push(node.summary(format!("{size} bytes"))).await;
        pos = pos
            .saturating_add(4)
            .saturating_add(len)
            .saturating_add(size);
    }
    cx.annotate(format!("OSM PBF, {blocks} blocks"));
    Ok(())
}
