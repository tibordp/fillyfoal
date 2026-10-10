//! Windows Prefetch files (`.pf`, `SCCA`).
//!
//! The header names the executable; the file information section (whose
//! layout depends on the version: 17 for XP, 23 for Vista/7, 26 for 8.1,
//! 30/31 for 10/11) gives the run count, last run times and the offsets of
//! the metrics, trace chains, file names and volumes. Windows 10 and later
//! usually store the file compressed (`MAM\x04`: Xpress Huffman with the
//! uncompressed size in the header); the decompressed file is dissected as
//! an uncompressed one.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::datakit::clip;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "prefetch",
    title: "Windows Prefetch",
    extensions: &["pf"],
    mime: "application/x-ms-prefetch",
    probe: Probe::Magic(&[(4, b"SCCA"), (0, b"MAM\x04")]),
    dissect: crate::expander!(dissect: Input),
};

const VERSIONS: EnumTable = &[
    (17, "Windows XP / 2003"),
    (23, "Windows Vista / 7"),
    (26, "Windows 8.1"),
    (30, "Windows 10"),
    (31, "Windows 11"),
];

record! {
    pub struct Header {
        version: u32 "Format version" .enumeration(VERSIONS),
        signature: ascii[4] "Signature",
        _unknown: u32 "Unknown",
        file_size: u32 "File size",
        executable: utf16[30] "Executable name",
        hash: u32 "Prefetch hash" .hex(),
        _flags: u32 "Unknown flags" .hex(),
    }
}

/// The parts of the file information section the dissector uses.
#[derive(Clone, Debug, Default)]
struct Info {
    metrics_offset: u32,
    metrics_count: u32,
    traces_offset: u32,
    traces_count: u32,
    names_offset: u32,
    names_size: u32,
    volumes_offset: u32,
    volumes_count: u32,
    volumes_size: u32,
    run_count: u32,
    last_run: Vec<u64>,
}

/// File information: common offsets, then version-specific run data.
fn file_info(f: &mut Fields<'_>, version: &u32) -> Result<Info> {
    let mut i = Info {
        metrics_offset: f.u32("Metrics array offset").hex().emit()?,
        metrics_count: f.u32("Metrics entries").emit()?,
        traces_offset: f.u32("Trace chains array offset").hex().emit()?,
        traces_count: f.u32("Trace chain entries").emit()?,
        names_offset: f.u32("Filename strings offset").hex().emit()?,
        names_size: f.u32("Filename strings size").hex().emit()?,
        volumes_offset: f.u32("Volumes information offset").hex().emit()?,
        volumes_count: f.u32("Volumes").emit()?,
        volumes_size: f.u32("Volumes information size").hex().emit()?,
        ..Info::default()
    };
    let runs = match version {
        17 => 1,
        23 => {
            f.u64("Unknown").emit()?;
            1
        }
        _ => {
            f.u64("Unknown").emit()?;
            8
        }
    };
    for n in 0..runs {
        let t = f
            .u64(match n {
                0 => "Last run time",
                _ => "Previous run time",
            })
            .filetime()
            .emit()?;
        if t != 0 {
            i.last_run.push(t);
        }
    }
    // Windows 10 has a variant with an 8-byte gap (metrics at 0x128).
    let gap = if matches!(version, 30 | 31) && i.metrics_offset == 0x128 {
        8
    } else {
        16
    };
    f.bytes("Unknown", gap).emit()?;
    i.run_count = f.u32("Run count").emit()?;
    Ok(i)
}

fn info_size(version: u32) -> u64 {
    match version {
        17 => 68,
        23 => 156,
        26 | 30 | 31 => 224,
        _ => 0,
    }
}

struct Pf {
    file: Span,
    version: u32,
    info: Info,
}

type P = Arc<Pf>;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read_avail(file.sub(0, 8)).await?;
    if magic.starts_with(b"MAM\x04") {
        let size = u32_le(&magic, 4).unwrap_or(0);
        cx.annotate(format!(
            "Windows Prefetch (compressed, {size} bytes uncompressed)"
        ));
        cx.emit(struct_node(
            "Compression header",
            file.sub(0, 8),
            LE,
            (),
            |f, _| {
                f.ascii("Signature", 3).emit()?;
                f.u8("Compression").desc("4 = Xpress Huffman").emit()?;
                f.u32("Uncompressed size").emit()?;
                Ok(())
            },
        ));
        cx.emit(crate::formats::content(
            "Decompressed",
            input,
            file.tail(8),
            crate::codec::Codec::XpressHuffman { size: size.into() },
            Some(size.into()),
        ));
        cx.emit(Node::new("Compressed data").span(file.tail(8)));
        return Ok(());
    }
    let header_span = file.sub(0, Header::SIZE);
    let header = parse(&cx, header_span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, LE));
    let size = info_size(header.version);
    if size == 0 {
        return Err(
            Diagnostic::unsupported(format!("prefetch version {}", header.version))
                .at(file.sub(0, 4)),
        );
    }
    let info_span = file.sub(Header::SIZE, size);
    let info = parse(&cx, info_span, LE, &header.version, file_info).await?;
    cx.emit(struct_node(
        "File information",
        info_span,
        LE,
        header.version,
        file_info,
    ));
    let mut summary = format!(
        "Windows Prefetch v{}, {}, run {} times",
        header.version, header.executable, info.run_count
    );
    if let Some(&t) = info.last_run.first() {
        summary = format!(
            "{summary}, last {}",
            crate::render::value(&Value::Timestamp {
                unix_seconds: crate::text::filetime_to_unix(t)
            })
        );
    }
    cx.annotate(summary);

    let pf: P = Arc::new(Pf {
        file,
        version: header.version,
        info: info.clone(),
    });
    let metric_size: u64 = if header.version == 17 { 20 } else { 32 };
    let metrics = file.sub(
        info.metrics_offset.into(),
        u64::from(info.metrics_count).saturating_mul(metric_size),
    );
    cx.emit(
        Node::new("Metrics")
            .span(metrics)
            .summary(format!("{} entries", info.metrics_count))
            .lazy(metrics_list, pf.clone()),
    );
    let trace_size: u64 = if header.version <= 26 { 12 } else { 8 };
    cx.emit(
        Node::new("Trace chains")
            .span(file.sub(
                info.traces_offset.into(),
                u64::from(info.traces_count).saturating_mul(trace_size),
            ))
            .summary(format!("{} entries", info.traces_count)),
    );
    let names = file.sub(info.names_offset.into(), info.names_size.into());
    cx.emit(
        Node::new("Filename strings")
            .span(names)
            .lazy(utf16_strings, names),
    );
    let volumes = file.sub(info.volumes_offset.into(), info.volumes_size.into());
    cx.emit(
        Node::new("Volumes")
            .span(volumes)
            .summary(format!("{}", info.volumes_count))
            .lazy(volumes_list, pf),
    );
    Ok(())
}

/// A region of consecutive NUL-terminated UTF-16 strings, listed in pages.
async fn utf16_strings(cx: Cx, span: Span) -> Result<()> {
    let mut at = 0u64;
    let mut index = 0u64;
    while at < span.len {
        let data = cx.read_avail(span.sub(at, 0x1000)).await?;
        let (text, used, terminated) = crate::text::utf16z(&data, LE);
        if !terminated && to_u64(data.len()) == 0x1000 {
            return Err(
                Diagnostic::limit("string longer than 2048 characters").at(span.sub(at, 0x1000))
            );
        }
        let used = to_u64(used).max(2);
        if !text.is_empty() {
            cx.push(
                Node::new(format!("[{index}]"))
                    .span(span.sub(at, used))
                    .value(Value::Text(text)),
            )
            .await;
            index = index.saturating_add(1);
        }
        at = at.saturating_add(used);
        if !terminated {
            break;
        }
        cx.checkpoint().await;
    }
    Ok(())
}

/// The file name a metrics or volume entry points to.
async fn name_at(cx: &Cx, region: Span, offset: u32, chars: u32) -> String {
    let span = region.sub(
        offset.into(),
        u64::from(chars).saturating_mul(2).min(0x2000),
    );
    cx.read_avail(span)
        .await
        .map(|b| crate::text::utf16(&b, LE))
        .unwrap_or_default()
}

async fn metrics_list(cx: Cx, pf: P) -> Result<()> {
    let size: u64 = if pf.version == 17 { 20 } else { 32 };
    let table = pf.file.sub_exact(
        pf.info.metrics_offset.into(),
        u64::from(pf.info.metrics_count).saturating_mul(size),
    )?;
    let names = pf
        .file
        .sub(pf.info.names_offset.into(), pf.info.names_size.into());
    cx.set_count(Count::Exact(pf.info.metrics_count.into()));
    for i in 0..u64::from(pf.info.metrics_count) {
        let span = table.sub(i.saturating_mul(size), size);
        let data = cx.read(span).await?;
        let at = if pf.version == 17 { 8 } else { 12 };
        let offset = u32_le(&data, at).unwrap_or(0);
        let chars = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
        let name = name_at(&cx, names, offset, chars).await;
        cx.push(
            crate::fields::struct_node(clip(&name, 160), span, LE, pf.version, metric)
                .summary(format!("metrics entry {i}")),
        )
        .await;
    }
    Ok(())
}

fn metric(f: &mut Fields<'_>, version: &u32) -> Result<()> {
    f.u32("Start time").emit()?;
    f.u32("Duration").emit()?;
    if *version != 17 {
        f.u32("Average duration").emit()?;
    }
    f.u32("Filename offset").hex().emit()?;
    f.u32("Filename length").emit()?;
    f.u32("Flags").hex().emit()?;
    if *version != 17 {
        f.u64("NTFS file reference")
            .hex()
            .with(|&r, n| {
                n.summary(format!(
                    "MFT entry {}, sequence {}",
                    r & 0xffff_ffff_ffff,
                    r >> 48
                ))
            })
            .emit()?;
    }
    Ok(())
}

async fn volumes_list(cx: Cx, pf: P) -> Result<()> {
    let size: u64 = match pf.version {
        17 => 40,
        30 | 31 => 96,
        _ => 104,
    };
    let region = pf
        .file
        .sub(pf.info.volumes_offset.into(), pf.info.volumes_size.into());
    let table = region.sub_exact(0, u64::from(pf.info.volumes_count).saturating_mul(size))?;
    for i in 0..u64::from(pf.info.volumes_count) {
        let span = table.sub(i.saturating_mul(size), size);
        let data = cx.read(span).await?;
        let path = name_at(
            &cx,
            region,
            u32_le(&data, 0).unwrap_or(0),
            u32_le(&data, 4).unwrap_or(0),
        )
        .await;
        let created = u64_le(&data, 8).unwrap_or(0);
        let serial = u32_le(&data, 16).unwrap_or(0);
        cx.push(
            Node::new(clip(&path, 120))
                .span(span)
                .value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(created),
                })
                .summary(format!(
                    "serial {:04X}-{:04X}",
                    serial >> 16,
                    serial & 0xffff
                ))
                .lazy(volume, (region, span)),
        )
        .await;
    }
    Ok(())
}

async fn volume(cx: Cx, (region, span): (Span, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 36)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Device path offset").hex().emit()?;
    f.u32("Device path length").emit()?;
    f.u64("Creation time").filetime().emit()?;
    f.u32("Serial number").hex().emit()?;
    let refs = f.u32("File references offset").hex().emit()?;
    let refs_size = f.u32("File references size").hex().emit()?;
    let dirs = f.u32("Directory strings offset").hex().emit()?;
    let dirs_count = f.u32("Directory strings").emit()?;
    if refs_size > 0 {
        cx.emit(Node::new("File references").span(region.sub(refs.into(), refs_size.into())));
    }
    if dirs_count > 0 {
        let dirs = region.tail(dirs.into());
        cx.emit(
            Node::new("Directory strings")
                .summary(format!("{dirs_count}"))
                .lazy(dir_strings, (dirs, dirs_count)),
        );
    }
    Ok(())
}

/// Directory strings: `u16 length` (characters), UTF-16 text, NUL.
async fn dir_strings(cx: Cx, (span, count): (Span, u32)) -> Result<()> {
    let mut at = 0u64;
    for _ in 0..count {
        let len = cx.read(span.sub_exact(at, 2)?).await?;
        let chars = u64::from(crate::bytes::u16_le(&len, 0).unwrap_or(0));
        let total = chars.saturating_add(1).saturating_mul(2).saturating_add(2);
        let text = cx
            .read(span.sub_exact(at.saturating_add(2), chars.saturating_mul(2))?)
            .await?;
        cx.push(
            Node::new("Directory")
                .span(span.sub(at, total))
                .value(Value::Text(crate::text::utf16(&text, LE))),
        )
        .await;
        at = at.saturating_add(total);
    }
    Ok(())
}
