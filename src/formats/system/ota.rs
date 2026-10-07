//! Android A/B OTA update payloads (`payload.bin`).

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe, embedded_as};
use crate::node::Node;

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Android A/B OTA payload

declare_format!(pub OTA_PAYLOAD = "ota-payload", "Android OTA update payload", ["bin"], "application/x-android-ota",
    Probe::Magic(&[(0, b"CrAU")]), ota_payload);

async fn ota_payload(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    let version = f.u64("Format version").emit()?;
    let manifest = f.u64("Manifest size").emit()?;
    let signature = if version >= 2 {
        f.u32("Metadata signature size").emit()?
    } else {
        0
    };
    let at = if version >= 2 { 24u64 } else { 20 };
    // DeltaArchiveManifest, shown without its schema.
    cx.emit(embedded_as(
        "Manifest (protobuf)",
        input.nested(file.sub(at, manifest)),
        &crate::formats::data::wire::protobuf::FORMAT,
    ));
    let sig_at = at.saturating_add(manifest);
    if signature > 0 {
        cx.emit(Node::new("Metadata signature").span(file.sub(sig_at, signature.into())));
    }
    cx.emit(Node::new("Data blobs").span(file.tail(sig_at.saturating_add(signature.into()))));
    cx.annotate(format!(
        "Android OTA payload v{version}, manifest {manifest} bytes"
    ));
    Ok(())
}
