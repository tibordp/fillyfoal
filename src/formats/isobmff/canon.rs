//! `uuid` boxes with well-known user types, and Canon CR3 metadata boxes
//! (`CNCV`, `CCTP`, `CTBO`, `CMT1`..`CMT4`, `THMB`, `PRVW`).

use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Fields;
use crate::formats::vidutil::{Entry, find, table};
use crate::formats::embedded;
use crate::node::Node;
use crate::record;

use super::{BE, BoxState, children};

const CANON: [u8; 16] = [
    0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48,
];
const CANON_PREVIEW: [u8; 16] = [
    0xea, 0xf4, 0x2b, 0x5e, 0x1c, 0x98, 0x4b, 0x88, 0xb9, 0xfb, 0xb7, 0xdc, 0x40, 0x6e, 0x4d, 0x16,
];
const XMP: [u8; 16] = [
    0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac,
];
const SPHERICAL: [u8; 16] = [
    0xff, 0xcc, 0x82, 0x63, 0xf8, 0x55, 0x4a, 0x93, 0x88, 0x14, 0x58, 0x7a, 0x02, 0x52, 0x1f, 0xdd,
];

const KNOWN: &[([u8; 4], &str)] = &[
    ([0x85, 0xc0, 0xb6, 0x87], "Canon CR3 metadata"),
    ([0xea, 0xf4, 0x2b, 0x5e], "Canon preview"),
    ([0xbe, 0x7a, 0xcf, 0xcb], "XMP metadata"),
    ([0xff, 0xcc, 0x82, 0x63], "Spherical video metadata"),
    ([0x6d, 0x1d, 0x9b, 0x05], "PIFF fragment time (tfxd)"),
    ([0xd4, 0x80, 0x7e, 0xf2], "PIFF fragment reference (tfrf)"),
    ([0xa2, 0x39, 0x4f, 0x52], "PIFF sample encryption"),
    ([0x89, 0x74, 0xdb, 0xce], "PIFF track encryption"),
    ([0xd0, 0x8a, 0x4f, 0x18], "PIFF protection system header"),
    ([0x55, 0x53, 0x4d, 0x54], "Sony USMT metadata"),
    ([0x50, 0x52, 0x4f, 0x46], "Sony PROF metadata"),
];

/// The name of a well-known `uuid` user type.
pub fn uuid_name(u: &[u8; 16]) -> Option<&'static str> {
    KNOWN
        .iter()
        .find(|(prefix, _)| u.starts_with(prefix))
        .map(|(_, n)| *n)
}

record! {
    pub struct TrackOffset {
        index: u32 "Index",
        offset: u64 "Offset" .hex(),
        size: u64 "Size",
    }
}

impl Entry for TrackOffset {
    fn summary(&self) -> Option<String> {
        Some(format!("{} bytes at {:#x}", self.size, self.offset))
    }
}

/// Decodes `uuid` boxes and Canon boxes. Returns `false` for other types.
pub async fn decode(cx: &Cx, st: &BoxState) -> Result<bool> {
    let body = st.body();
    let ctx = st.ctx;
    if let Some(u) = st.header.uuid {
        match u {
            CANON => children(cx, st.input, body, ctx.child_of(*b"uuid", body)).await?,
            CANON_PREVIEW => {
                let block = cx.block(body.sub(0, 8)).await?;
                let mut f = Fields::emitting(cx, &block, BE);
                f.u32("Unknown").hex().emit()?;
                f.u32("Unknown").hex().emit()?;
                let rest = body.tail(8);
                children(cx, st.input, rest, ctx.child_of(*b"uuid", rest)).await?;
            }
            XMP | SPHERICAL => cx.emit(embedded("XML", st.input.nested(body))),
            _ => cx.emit(Node::new("Data").span(body)),
        }
        return Ok(true);
    }
    match &st.header.kind {
        b"CNCV" => {
            let block = cx.block(body.sub(0, 0x100)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            let n = f.remaining();
            f.ascii("Compressor version", n).emit()?;
        }
        b"CCTP" => {
            let block = cx.block(body.sub(0, 12)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            f.u32("Unknown").emit()?;
            f.u32("Unknown").emit()?;
            f.u32("Track count").emit()?;
            let rest = body.tail(12);
            children(cx, st.input, rest, ctx.child_of(*b"CCTP", rest)).await?;
        }
        b"CCDT" => {
            let block = cx.block(body.sub(0, 16)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            f.u64("Image type").hex().emit()?;
            f.u32("Dual pixel").emit()?;
            f.u32("Track index").emit()?;
        }
        b"CTBO" => {
            let block = cx.block(body.sub(0, 4)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            let n = f.u32("Entry count").emit()?;
            cx.emit(table::<TrackOffset>("Entries", body.tail(4), n.into(), BE));
        }
        b"CMT1" | b"CMT2" | b"CMT3" | b"CMT4" => {
            let name = match &st.header.kind {
                b"CMT1" => "IFD0 (TIFF)",
                b"CMT2" => "Exif IFD (TIFF)",
                b"CMT3" => "Canon makernote (TIFF)",
                _ => "GPS IFD (TIFF)",
            };
            cx.emit(embedded(name, st.input.nested(body)));
        }
        b"THMB" | b"PRVW" => {
            let head = cx.read_avail(body.sub(0, 32)).await?;
            let block = cx.block(body.sub(0, 4)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            f.u32("Unknown").hex().emit()?;
            let fields = body.sub(4, 12);
            if let Some(at) = find(&head, &[0xff, 0xd8, 0xff]) {
                let at = crate::bytes::to_u64(at);
                cx.emit(Node::new("Header").span(fields.sub(0, at.saturating_sub(4))));
                cx.emit(embedded("JPEG", st.input.nested(body.tail(at))));
            } else {
                cx.emit(Node::new("Data").span(body.tail(4)));
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}
