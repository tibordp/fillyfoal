//! Parallels disk images (`WithoutFreeSpace` / `WithouFreSpacExt`).
//!
//! A 64-byte header is followed by the block allocation table; each entry
//! locates a cluster (in sectors, or in clusters for the extended format).

use std::sync::Arc;

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, size};
use crate::formats::{Format, Input, Probe, dissect_or_data};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;

const LE: Endian = Endian::Little;
const SECTOR: u64 = 512;

pub static FORMAT: Format = Format {
    name: "parallels",
    title: "Parallels disk image",
    extensions: &["hdd", "hds"],
    mime: "application/x-parallels-disk",
    probe: Probe::Magic(&[(0, b"WithoutFreeSpace"), (0, b"WithouFreSpacExt")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    pub struct Header {
        magic: ascii[16] "Magic",
        version: u32 "Version",
        heads: u32 "Heads",
        cylinders: u32 "Cylinders",
        tracks: u32 "Sectors per cluster",
        bat_entries: u32 "BAT entries",
        sectors: u64 "Disk size (sectors)" .with(|&v, n| n.summary(size(v.saturating_mul(SECTOR)))),
        in_use: u32 "In use" .hex(),
        data_offset: u32 "Data offset (sectors)",
        flags: u32 "Flags" .hex(),
        ext_offset: u64 "Extension offset" .hex(),
    }
}

struct Image {
    input: Input,
    bat: Span,
    cluster: u64,
    /// BAT entries count clusters (extended format) rather than sectors.
    in_clusters: bool,
    size: u64,
}

impl Image {
    fn cluster_span(&self, entry: u32) -> Span {
        let unit = if self.in_clusters { self.cluster } else { SECTOR };
        self.input.span.sub(u64::from(entry).saturating_mul(unit), self.cluster)
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, Header::SIZE);
    let h = parse(&cx, span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", span, LE));
    let cluster = u64::from(h.tracks).saturating_mul(SECTOR);
    cx.annotate(format!(
        "Parallels disk image, {}, {} clusters",
        size(h.sectors.saturating_mul(SECTOR)),
        size(cluster)
    ));
    if cluster == 0 {
        return Err(Diagnostic::malformed("zero cluster size").at(span));
    }
    let image = Arc::new(Image {
        input,
        bat: file.sub_exact(Header::SIZE, u64::from(h.bat_entries).saturating_mul(4))?,
        cluster,
        in_clusters: h.magic == "WithouFreSpacExt",
        size: h.sectors.saturating_mul(SECTOR),
    });
    cx.emit(
        Node::new("Block allocation table")
            .span(image.bat)
            .summary(format!("{} entries", h.bat_entries))
            .lazy(bat, image.clone()),
    );
    cx.emit(Node::new("Virtual disk").summary(size(image.size)).lazy(virtual_disk, image));
    Ok(())
}

async fn bat(cx: Cx, image: Arc<Image>) -> Result<()> {
    let count = image.bat.len / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = image.bat.sub(i.saturating_mul(4), 4);
        let entry = u32_le(&cx.read(span).await?, 0).unwrap_or(0);
        let node = Node::new(format!("Cluster {i}")).span(span);
        cx.push(if entry == 0 {
            node.summary("not allocated")
        } else {
            node.summary(format!("at {entry}")).target(image.cluster_span(entry))
        })
        .await;
    }
    Ok(())
}

async fn virtual_disk(cx: Cx, image: Arc<Image>) -> Result<()> {
    let table = cx.read(image.bat).await?;
    let mut list = PieceList::new(image.bat);
    for raw in table.as_chunks::<4>().0 {
        let want = image.cluster.min(image.size.saturating_sub(list.len()));
        if want == 0 {
            break;
        }
        let step = match u32::from_le_bytes(*raw) {
            0 => list.hole(&cx, want),
            n => {
                list.data(image.cluster_span(n).sub(0, want));
                Ok(())
            }
        };
        if let Err(e) = step {
            cx.diag(e);
            break;
        }
    }
    let span = list.finish(&cx, "parallels-clusters")?;
    dissect_or_data(cx, image.input.nested(span)).await
}
