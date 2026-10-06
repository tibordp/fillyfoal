//! Dart kernel binaries (`.dill`, the output of the Dart front end and
//! the input to the VM and AOT compiler): magic, format version and the
//! SDK hash the file was built with.

use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::data_node;
use crate::formats::{Format, Input, Probe};

pub static FORMAT: Format = Format {
    name: "dart-kernel",
    title: "Dart kernel binary",
    extensions: &["dill"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"\x90\xab\xcd\xef")]),
    dissect: crate::expander!(dissect: Input),
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let block = cx.block(file.sub(0, 18)).await?;
    let mut f = Fields::emitting(&cx, &block, Endian::Big);
    f.u32("magic").hex().emit()?;
    let version = f.u32("formatVersion").emit()?;
    let hash = f
        .ascii("sdkHash", 10)
        .desc("Git hash of the SDK, or 0000000000")
        .emit()?;
    cx.annotate(format!("Dart kernel binary, format {version}, SDK {hash}"));
    cx.emit(data_node(
        "Component",
        file.tail(18),
        file.len.saturating_sub(18),
    ));
    Ok(())
}
