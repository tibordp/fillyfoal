//! Application packages: AppImage, Solaris datastream packages, Haiku
//! packages and Electron ASAR archives.

use crate::bytes::{u16_be, u16_le, u32_be, u32_le, u64_be, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::text::scan::head_lines;
use crate::formats::{Head, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::value::{Radix, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

// ---------------------------------------------------------------------------
// Packaging: AppImage, Solaris datastream, Haiku packages, Electron ASAR

fn appimage_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x7fELF") && (h.at(8, b"AI\x02") || h.at(8, b"AI\x01"))
}

declare_format!(pub APPIMAGE = "appimage", "AppImage", ["appimage"], "application/vnd.appimage",
    Probe::Custom(appimage_probe), appimage);

async fn appimage(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub(0, 64)).await?;
    let kind = h.get(10).copied().unwrap_or(0);
    let is64 = h.get(4) == Some(&2);
    let little = h.get(5) != Some(&2);
    let u16_at = |at: usize| {
        if little {
            u16_le(&h, at)
        } else {
            u16_be(&h, at)
        }
        .unwrap_or(0)
    };
    let (shoff, entsize, count) = if is64 {
        (
            if little {
                u64_le(&h, 0x28)
            } else {
                u64_be(&h, 0x28)
            }
            .unwrap_or(0),
            u16_at(0x3a),
            u16_at(0x3c),
        )
    } else {
        (
            u64::from(
                if little {
                    u32_le(&h, 0x20)
                } else {
                    u32_be(&h, 0x20)
                }
                .unwrap_or(0),
            ),
            u16_at(0x2e),
            u16_at(0x30),
        )
    };
    // The runtime ends with its section header table; the image follows.
    let end = shoff.saturating_add(u64::from(entsize).saturating_mul(count.into()));
    if end == 0 || end >= file.len {
        return Err(
            Diagnostic::malformed("cannot locate the end of the ELF runtime").at(file.sub(0, 64)),
        );
    }
    cx.emit(
        Node::new("AppImage type")
            .span(file.sub(8, 3))
            .value(uint(kind.into(), 8)),
    );
    cx.emit(embedded_as(
        "Runtime (ELF)",
        input.nested(file.sub(0, end)),
        &crate::formats::executable::elf::FORMAT,
    ));
    cx.emit(embedded(
        if kind == 1 {
            "Filesystem image (ISO 9660)"
        } else {
            "Filesystem image (SquashFS)"
        },
        input.nested(file.tail(end)),
    ));
    cx.annotate(format!("AppImage type {kind}, payload at {end:#x}"));
    Ok(())
}

declare_format!(pub SOLARIS_PKG = "solaris-pkg", "SVR4 package datastream", ["pkg"], "application/x-svr4-package",
    Probe::Magic(&[(0, b"# PaCkAgE DaTaStReAm\n")]), solaris_pkg);

async fn solaris_pkg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = head_lines(&cx, file, 8192).await?;
    let mut end = 0u64;
    let mut packages = Vec::new();
    for (line, span) in all.iter().skip(1) {
        if line.starts_with("# end of header") {
            end = span.end().saturating_sub(file.offset);
            break;
        }
        let mut parts = line.split_whitespace();
        if let (Some(name), Some(parts_n), Some(size)) = (parts.next(), parts.next(), parts.next())
        {
            packages.push(name.to_owned());
            cx.emit(
                Node::new(name.to_owned())
                    .span(*span)
                    .summary(format!("{parts_n} part(s), up to {size} blocks")),
            );
        }
    }
    cx.emit(Node::new("Header").span(file.sub(0, end)));
    let body = end.checked_next_multiple_of(512).unwrap_or(u64::MAX);
    cx.emit(embedded(
        "Package archives (cpio)",
        input.nested(file.tail(body)),
    ));
    cx.annotate(format!("SVR4 package datastream: {}", packages.join(", ")));
    Ok(())
}

declare_format!(pub HPKG = "haiku-package", "Haiku package", ["hpkg", "hpkr"], "application/x-haiku-package",
    Probe::Magic(&[(0, b"hpkg"), (0, b"hpkr")]), hpkg);

async fn hpkg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let repo = cx.read(file.sub(0, 4)).await? == b"hpkr";
    let head = cx.block(file.sub(0, 40)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Signature", 4).emit()?;
    let header = f.u16("Header size").emit()?;
    let version = f.u16("Version").emit()?;
    let total = f.u64("Total size").emit()?;
    f.u16("Minor version").emit()?;
    let compression = f
        .u16("Heap compression")
        .enumeration(&[(0, "none"), (1, "zlib"), (2, "zstd")])
        .emit()?;
    let chunk = f.u32("Heap chunk size").emit()?;
    let compressed = f.u64("Heap size (compressed)").emit()?;
    let uncompressed = f.u64("Heap size (uncompressed)").emit()?;
    let heap = file.sub(header.into(), compressed);
    cx.emit(Node::new("Heap").span(heap).summary(format!(
        "{uncompressed} bytes uncompressed in {chunk}-byte chunks"
    )));
    let _ = compression;
    cx.annotate(format!(
        "Haiku {} v{version}, {total} bytes",
        if repo { "repository" } else { "package" }
    ));
    Ok(())
}

fn asar_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(4) && h.at(16, b"{\"files\":")
}

declare_format!(pub ASAR = "asar", "Electron archive (ASAR)", ["asar"], "application/x-asar",
    Probe::Custom(asar_probe), asar);

async fn asar(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Size field length").emit()?;
    let header = f.u32("Header size").emit()?;
    f.u32("Header pickle payload").emit()?;
    let json = f.u32("Header JSON length").emit()?;
    cx.emit(embedded(
        "Header (JSON)",
        input.nested(file.sub(16, json.into())),
    ));
    let data = 8u64.saturating_add(header.into());
    cx.emit(
        Node::new("File data")
            .span(file.tail(data))
            .summary("offsets in the header are relative to here"),
    );
    cx.annotate(format!("Electron ASAR, {json}-byte index"));
    Ok(())
}
