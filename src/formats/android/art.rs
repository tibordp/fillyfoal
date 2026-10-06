//! Android ART boot/app images (`art\n`): the image header that ties the
//! image to its OAT file. Field layout depends on the version; versions
//! 074 and later (Android 10+) share the prefix decoded here.

use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::binutil::data_node;
use crate::formats::{Format, Input, Probe};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "art-image",
    title: "Android ART image",
    extensions: &["art"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| h.starts_with(b"art\n") && h.at(7, b"\0")),
    dissect: crate::expander!(dissect: Input),
};

const MODERN: &[&str] = &[
    "image_reservation_size",
    "component_count",
    "image_begin",
    "image_size",
    "image_checksum",
    "oat_checksum",
    "oat_file_begin",
    "oat_data_begin",
    "oat_data_end",
    "oat_file_end",
    "boot_image_begin",
    "boot_image_size",
    "boot_image_component_count",
    "boot_image_checksum",
    "image_roots",
    "pointer_size",
];

const LEGACY: &[&str] = &[
    "image_begin",
    "image_size",
    "oat_checksum",
    "oat_file_begin",
    "oat_data_begin",
    "oat_data_end",
    "oat_file_end",
    "boot_image_begin",
    "boot_image_size",
    "boot_oat_begin",
    "boot_oat_size",
    "patch_delta",
    "image_roots",
    "pointer_size",
    "compile_pic",
    "is_pic",
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 8)).await?;
    let version_text = crate::text::until_nul(head.get(4..8).unwrap_or_default());
    let version: u32 = version_text.parse().unwrap_or(0);
    let names = if version >= 74 { MODERN } else { LEGACY };
    let len = 8u64.saturating_add(u64::try_from(names.len()).unwrap_or(0).saturating_mul(4));
    let block = cx.block(file.sub(0, len)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("magic", 4).emit()?;
    f.ascii("version", 4).emit()?;
    let mut values = Vec::new();
    for name in names {
        let field = f.u32(name);
        let field = if name.ends_with("_count") || *name == "pointer_size" || name.starts_with("is_") || name.starts_with("compile_") {
            field
        } else {
            field.hex()
        };
        values.push((*name, field.emit()?));
    }
    let get = |n: &str| values.iter().find(|(k, _)| *k == n).map_or(0, |(_, v)| *v);
    cx.annotate(format!(
        "Android ART image v{version_text}, image {:#x}+{:#x}, OAT data {:#x}..{:#x}, {}-bit",
        get("image_begin"),
        get("image_size"),
        get("oat_data_begin"),
        get("oat_data_end"),
        get("pointer_size").saturating_mul(8)
    ));
    cx.emit(data_node("Image contents", file.tail(len), file.len.saturating_sub(len)));
    Ok(())
}
