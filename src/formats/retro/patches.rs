//! Binary patch formats used for ROM hacks, translations and software
//! updates: IPS (and EBP), IPS32, UPS, BPS, VCDIFF (xdelta3), bsdiff, PPF, APS,
//! GDIFF, Ninja RUP and Windows delta (PA30).

use super::util::{
    Varint, crc_node, crc32_of, dec, find_zero, hex, size, text, uint_be, varint, varint_field,
};
use crate::bytes::{u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// IPS and IPS32

declare_format!(pub IPS = "ips", "International Patching System patch", ["ips"],
    "application/x-ips-patch", Probe::Magic(&[(0, b"PATCH")]), ips);
declare_format!(pub IPS32 = "ips32", "IPS32 patch (32-bit offsets)", ["ips32", "ips"],
    "application/x-ips-patch", Probe::Magic(&[(0, b"IPS32")]), ips32);

async fn ips(cx: Cx, input: Input) -> Result<()> {
    ips_walk(cx, input, 3, b"EOF").await
}

async fn ips32(cx: Cx, input: Input) -> Result<()> {
    ips_walk(cx, input, 4, b"EEOF").await
}

/// Layout of one record; `width` is the size of the offset field.
fn ips_record(f: &mut Fields<'_>, width: &u64) -> Result<()> {
    uint_be(f, "Offset", *width)?;
    let len = f.u16("Size").emit()?;
    if len == 0 {
        f.u16("RLE run length").emit()?;
        f.u8("RLE value").hex().emit()?;
    } else {
        f.node(Node::new("Data").span(f.peek_span(len.into())));
        f.skip(len.into());
    }
    Ok(())
}

async fn ips_walk(cx: Cx, input: Input, width: u64, eof: &'static [u8]) -> Result<()> {
    let file = input.span;
    let (name, magic) = if width == 3 {
        ("IPS", "PATCH")
    } else {
        ("IPS32", "IPS32")
    };
    cx.emit(Node::new("Magic").span(file.sub(0, 5)).value(text(magic)));
    cx.annotate(format!("{name} patch"));
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(5);
    let (mut records, mut rle, mut end) = (0u64, 0u64, 0u64);
    let mut terminated = false;
    while cur.remaining() >= width {
        let start = cur.pos();
        let raw = cur.bytes(width).await?;
        if raw == eof {
            cx.emit(
                Node::new("End marker")
                    .span(cur.since(start))
                    .value(text(String::from_utf8_lossy(eof))),
            );
            terminated = true;
            break;
        }
        let offset = raw.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
        let len = cur.u16().await?;
        let (written, summary) = if len == 0 {
            let run = cur.u16().await?;
            let value = cur.u8().await?;
            rle = rle.saturating_add(1);
            (
                u64::from(run),
                format!("{run} × {value:#04x} at {offset:#x} (RLE)"),
            )
        } else {
            cur.skip(len.into());
            (u64::from(len), format!("{len} bytes at {offset:#x}"))
        };
        end = end.max(offset.saturating_add(written));
        records = records.saturating_add(1);
        let span = cur.since(start);
        let mut node = struct_node(format!("Record {records}"), span, BE, width, ips_record)
            .value(hex(offset, 32))
            .summary(summary);
        if cur.pos() > file.len {
            node = node.diag(Diagnostic::truncated(
                span,
                file.len
                    .saturating_sub(span.offset.saturating_sub(file.offset)),
            ));
        }
        cx.push(node).await;
    }
    let mut truncate = None;
    let mut ebp = false;
    if terminated && cur.peek(1).await?.first() == Some(&b'{') {
        // EarthBound patches (EBP) append JSON metadata after the IPS body.
        cx.emit(embedded(
            "Metadata (EBP JSON)",
            input.nested(file.tail(cur.pos())),
        ));
        ebp = true;
    } else if terminated && cur.remaining() >= 3 {
        let start = cur.pos();
        let raw = cur.bytes(cur.remaining().min(4)).await?;
        let value = raw.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
        truncate = Some(value);
        cx.emit(
            Node::new("Truncate target to")
                .span(cur.since(start))
                .value(hex(value, 32)),
        );
    }
    if !terminated {
        cx.diag(Diagnostic::warning("no end-of-file marker"));
    }
    cx.annotate(format!(
        "{}{name} patch, {records} records ({rle} RLE), writes up to {end:#x}{}",
        if ebp { "EBP (EarthBound) " } else { "" },
        truncate.map_or_else(String::new, |t| format!(", truncates to {t:#x}"))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// UPS

declare_format!(pub UPS = "ups", "Universal Patching System patch", ["ups"],
    "application/x-ups-patch", Probe::Magic(&[(0, b"UPS1")]), ups);

/// Emits the three CRC-32s that end UPS and BPS patches, verifying the last.
async fn beat_footer(cx: &Cx, file: Span) -> Result<bool> {
    let at = file.len.saturating_sub(12);
    let footer = cx.read(file.sub(at, 12)).await?;
    let computed = crc32_of(cx, file.sub(0, file.len.saturating_sub(4))).await;
    let stored = u32_le(&footer, 8).unwrap_or(0);
    cx.emit(
        Node::new("Source CRC-32")
            .span(file.sub(at, 4))
            .value(hex(u32_le(&footer, 0).unwrap_or(0).into(), 32)),
    );
    cx.emit(
        Node::new("Target CRC-32")
            .span(file.sub(at.saturating_add(4), 4))
            .value(hex(u32_le(&footer, 4).unwrap_or(0).into(), 32)),
    );
    cx.emit(crc_node(
        "Patch CRC-32",
        file.sub(at.saturating_add(8), 4),
        stored,
        computed,
    ));
    Ok(computed == Some(stored))
}

async fn ups(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if file.len < 16 {
        return Err(Diagnostic::truncated(file.sub(0, 16), file.len));
    }
    let body_end = file.len.saturating_sub(12);
    let mut cur = Cursor::new(&cx, file, LE);
    cx.emit(Node::new("Magic").span(cur.span(4)).value(text("UPS1")));
    cur.skip(4);
    let source = varint_field(&cx, &mut cur, Varint::Beat, "Source size").await?;
    let target = varint_field(&cx, &mut cur, Varint::Beat, "Target size").await?;
    let crc_ok = beat_footer(&cx, file).await?;
    let body = file.sub(0, body_end);
    let (mut hunks, mut offset, mut changed) = (0u64, 0u64, 0u64);
    while cur.pos() < body_end {
        let start = cur.pos();
        let skip = varint(&mut cur, Varint::Beat).await?;
        offset = offset.saturating_add(skip);
        let data = cur.pos();
        let Some(zero) = find_zero(&cx, body, data).await? else {
            cx.push(
                Node::new("Hunk")
                    .span(cur.since(start))
                    .diag(Diagnostic::malformed("XOR data not terminated")),
            )
            .await;
            break;
        };
        let len = zero.saturating_sub(data);
        cur.seek(zero.saturating_add(1));
        hunks = hunks.saturating_add(1);
        changed = changed.saturating_add(len);
        cx.push(
            Node::new(format!("Hunk {hunks}"))
                .span(cur.since(start))
                .value(hex(offset, 64))
                .summary(format!("{len} bytes XORed at {offset:#x}"))
                .lazy(
                    ups_hunk,
                    (cur.since(start), data.saturating_sub(start), len),
                ),
        )
        .await;
        offset = offset.saturating_add(len).saturating_add(1);
    }
    cx.annotate(format!(
        "UPS patch, {} → {}, {hunks} hunks changing {changed} bytes, patch CRC {}",
        size(source),
        size(target),
        if crc_ok { "valid" } else { "not verified" }
    ));
    Ok(())
}

async fn ups_hunk(cx: Cx, (span, skip_len, len): (Span, u64, u64)) -> Result<()> {
    cx.emit(Node::new("Relative offset").span(span.sub(0, skip_len)));
    cx.emit(Node::new("XOR data").span(span.sub(skip_len, len)));
    cx.emit(Node::new("Terminator").span(span.sub(skip_len.saturating_add(len), 1)));
    Ok(())
}

// ---------------------------------------------------------------------------
// BPS

declare_format!(pub BPS = "bps", "Beat patch (BPS)", ["bps"],
    "application/x-bps-patch", Probe::Magic(&[(0, b"BPS1")]), bps);

const BPS_ACTIONS: [&str; 4] = ["SourceRead", "TargetRead", "SourceCopy", "TargetCopy"];

async fn bps(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if file.len < 16 {
        return Err(Diagnostic::truncated(file.sub(0, 16), file.len));
    }
    let body_end = file.len.saturating_sub(12);
    let mut cur = Cursor::new(&cx, file, LE);
    cx.emit(Node::new("Magic").span(cur.span(4)).value(text("BPS1")));
    cur.skip(4);
    let source = varint_field(&cx, &mut cur, Varint::Beat, "Source size").await?;
    let target = varint_field(&cx, &mut cur, Varint::Beat, "Target size").await?;
    let meta_len = varint_field(&cx, &mut cur, Varint::Beat, "Metadata size").await?;
    if meta_len > 0 {
        let span = cur.span(meta_len);
        let bytes = cx.read_avail(span.sub(0, 4096)).await?;
        let mut node = Node::new("Metadata").span(span);
        if crate::text::looks_like_text(&bytes) {
            node = node.value(text(String::from_utf8_lossy(&bytes).into_owned()));
        }
        cx.emit(node);
        cur.skip(meta_len);
    }
    let crc_ok = beat_footer(&cx, file).await?;
    let (mut actions, mut out, mut source_rel, mut target_rel) = (0u64, 0u64, 0i128, 0i128);
    let mut counts = [0u64; 4];
    while cur.pos() < body_end {
        let start = cur.pos();
        let data = varint(&mut cur, Varint::Beat).await?;
        let kind = usize::try_from(data & 3).unwrap_or(0);
        let len = (data >> 2).saturating_add(1);
        let summary = match kind {
            0 => format!("{len} bytes from source {out:#x}"),
            1 => {
                cur.skip(len);
                format!("{len} literal bytes")
            }
            _ => {
                let raw = varint(&mut cur, Varint::Beat).await?;
                let delta = i128::from(raw >> 1);
                let delta = if raw & 1 != 0 {
                    delta.saturating_neg()
                } else {
                    delta
                };
                let rel = if kind == 2 {
                    &mut source_rel
                } else {
                    &mut target_rel
                };
                *rel = rel.saturating_add(delta);
                let from = *rel;
                *rel = rel.saturating_add(i128::from(len));
                format!(
                    "{len} bytes from {} {from:#x}",
                    if kind == 2 { "source" } else { "target" }
                )
            }
        };
        if let Some(c) = counts.get_mut(kind) {
            *c = c.saturating_add(1);
        }
        actions = actions.saturating_add(1);
        let name = BPS_ACTIONS.get(kind).copied().unwrap_or("?");
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .value(hex(out, 64))
                .summary(summary),
        )
        .await;
        out = out.saturating_add(len);
    }
    if out != target {
        cx.diag(Diagnostic::warning(format!(
            "actions produce {out} bytes, header says {target}"
        )));
    }
    let [sr, tr, sc, tc] = counts;
    cx.annotate(format!(
        "BPS patch, {} → {}, {actions} actions ({sr} SourceRead, {tr} TargetRead, {sc} SourceCopy, {tc} TargetCopy), patch CRC {}",
        size(source),
        size(target),
        if crc_ok { "valid" } else { "not verified" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// VCDIFF (RFC 3284), as written by xdelta3 and open-vcdiff

declare_format!(pub VCDIFF = "vcdiff", "VCDIFF delta (xdelta3)", ["vcdiff", "xdelta", "xd3", "vcd"],
    "application/vcdiff", Probe::Magic(&[(0, b"\xd6\xc3\xc4\x00")]), vcdiff);

const VCD_HDR: FlagTable = &[
    flag(1, "VCD_DECOMPRESS"),
    flag(2, "VCD_CODETABLE"),
    flag(4, "VCD_APPHEADER"),
];
const VCD_WIN: FlagTable = &[
    flag(1, "VCD_SOURCE"),
    flag(2, "VCD_TARGET"),
    flag(4, "VCD_ADLER32"),
];
const VCD_DELTA: FlagTable = &[
    flag(1, "VCD_DATACOMP"),
    flag(2, "VCD_INSTCOMP"),
    flag(4, "VCD_ADDRCOMP"),
];
const VCD_COMPRESSORS: EnumTable = &[(1, "DJW"), (2, "LZMA"), (16, "FGK")];

async fn vcdiff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    cx.emit(Node::new("Magic").span(cur.span(3)));
    cur.skip(3);
    let version = cur.u8().await?;
    cx.emit(
        Node::new("Version")
            .span(file.sub(3, 1))
            .value(dec(version.into(), 8)),
    );
    let indicator = cur.u8().await?;
    let (set, unknown) = crate::value::decode_flags(VCD_HDR, indicator.into());
    cx.emit(
        Node::new("Header indicator")
            .span(file.sub(4, 1))
            .value(Value::Flags {
                raw: indicator.into(),
                bits: 8,
                set,
                unknown,
            }),
    );
    if indicator & 1 != 0 {
        let at = cur.pos();
        let id = cur.u8().await?;
        cx.emit(
            Node::new("Secondary compressor")
                .span(cur.since(at))
                .value(Value::Enum {
                    raw: id.into(),
                    bits: 8,
                    name: lookup(VCD_COMPRESSORS, id.into()),
                }),
        );
    }
    if indicator & 2 != 0 {
        let len = varint_field(&cx, &mut cur, Varint::Vcdiff, "Code table length").await?;
        cx.emit(Node::new("Code table").span(cur.span(len)));
        cur.skip(len);
    }
    let mut app = None;
    if indicator & 4 != 0 {
        let len = varint_field(&cx, &mut cur, Varint::Vcdiff, "Application header length").await?;
        let span = cur.span(len);
        let bytes = cx.read_avail(span.sub(0, 1024)).await?;
        // xdelta3 stores "target/encoding/source/encoding/".
        let header = String::from_utf8_lossy(&bytes).into_owned();
        cx.emit(
            Node::new("Application header")
                .span(span)
                .value(text(header.clone())),
        );
        app = Some(header);
        cur.skip(len);
    }
    let (mut windows, mut total) = (0u64, 0u64);
    while !cur.at_end() {
        let start = cur.pos();
        let win = cur.u8().await?;
        let mut source = None;
        if win & 3 != 0 {
            let len = varint(&mut cur, Varint::Vcdiff).await?;
            let pos = varint(&mut cur, Varint::Vcdiff).await?;
            source = Some((len, pos));
        }
        let delta_len = varint(&mut cur, Varint::Vcdiff).await?;
        let delta_start = cur.pos();
        let target_len = varint(&mut cur, Varint::Vcdiff).await?;
        cur.seek(delta_start.saturating_add(delta_len));
        windows = windows.saturating_add(1);
        total = total.saturating_add(target_len);
        let span = cur.since(start);
        let mut summary = format!(
            "{target_len} bytes at {:#x}",
            total.saturating_sub(target_len)
        );
        if let Some((len, pos)) = source {
            summary.push_str(&format!(
                ", copies from {} {pos:#x}+{len:#x}",
                if win & 1 != 0 { "source" } else { "target" }
            ));
        }
        let mut node = Node::new(format!("Window {windows}"))
            .span(span)
            .summary(summary)
            .lazy(vcdiff_window, span);
        if cur.pos() > file.len {
            node = node.diag(Diagnostic::truncated(span, file.len.saturating_sub(start)));
        }
        cx.push(node).await;
    }
    let names = app.as_deref().map(|a| {
        let parts: Vec<&str> = a.split('/').collect();
        format!(
            ", {:?} from {:?}",
            parts.first().copied().unwrap_or(""),
            parts.get(2).copied().unwrap_or("")
        )
    });
    cx.annotate(format!(
        "VCDIFF delta, {windows} windows, {total} target bytes{}",
        names.unwrap_or_default()
    ));
    Ok(())
}

async fn vcdiff_window(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    let win = cur.u8().await?;
    let (set, unknown) = crate::value::decode_flags(VCD_WIN, win.into());
    cx.emit(
        Node::new("Window indicator")
            .span(span.sub(0, 1))
            .value(Value::Flags {
                raw: win.into(),
                bits: 8,
                set,
                unknown,
            }),
    );
    if win & 3 != 0 {
        varint_field(&cx, &mut cur, Varint::Vcdiff, "Source segment length").await?;
        varint_field(&cx, &mut cur, Varint::Vcdiff, "Source segment position").await?;
    }
    varint_field(&cx, &mut cur, Varint::Vcdiff, "Delta encoding length").await?;
    varint_field(&cx, &mut cur, Varint::Vcdiff, "Target window length").await?;
    let at = cur.pos();
    let delta = cur.u8().await?;
    let (set, unknown) = crate::value::decode_flags(VCD_DELTA, delta.into());
    cx.emit(
        Node::new("Delta indicator")
            .span(cur.since(at))
            .value(Value::Flags {
                raw: delta.into(),
                bits: 8,
                set,
                unknown,
            }),
    );
    let data = varint_field(&cx, &mut cur, Varint::Vcdiff, "Data section length").await?;
    let inst = varint_field(&cx, &mut cur, Varint::Vcdiff, "Instructions section length").await?;
    let addr = varint_field(&cx, &mut cur, Varint::Vcdiff, "Addresses section length").await?;
    if win & 4 != 0 {
        let at = cur.pos();
        let sum = cur.u32().await?;
        cx.emit(
            Node::new("Adler-32")
                .span(cur.since(at))
                .value(hex(sum.into(), 32)),
        );
    }
    for (name, len) in [
        ("Data section", data),
        ("Instructions section", inst),
        ("Addresses section", addr),
    ] {
        cx.emit(Node::new(name).span(cur.span(len)).summary(size(len)));
        cur.skip(len);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bsdiff (BSDIFF40 and Android's BSDF2), Matthew Endsley's BSDIFF43

declare_format!(pub BSDIFF = "bsdiff", "bsdiff binary patch", ["bsdiff", "bsdiff40", "patch", "diff"],
    "application/x-bsdiff", Probe::Magic(&[(0, b"BSDIFF40"), (0, b"BSDF2")]), bsdiff);
declare_format!(pub BSDIFF43 = "bsdiff43", "bsdiff patch (ENDSLEY/BSDIFF43)", ["bsdiff", "patch"],
    "application/x-bsdiff", Probe::Magic(&[(0, b"ENDSLEY/BSDIFF43")]), bsdiff43);

const BSDF2_CODECS: EnumTable = &[(0, "raw"), (1, "bzip2"), (2, "brotli")];

/// bsdiff's `offtout`: 64-bit sign-magnitude, little-endian.
fn offtin(raw: u64) -> i64 {
    let magnitude = i64::try_from(raw & 0x7fff_ffff_ffff_ffff).unwrap_or(i64::MAX);
    if raw >> 63 != 0 {
        magnitude.saturating_neg()
    } else {
        magnitude
    }
}

async fn bsdiff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let bsdf2 = head.data.starts_with(b"BSDF2");
    let mut codecs = [1u8; 3];
    if bsdf2 {
        f.ascii("Magic", 5).emit()?;
        for (i, name) in [
            "Control block codec",
            "Diff block codec",
            "Extra block codec",
        ]
        .into_iter()
        .enumerate()
        {
            let codec = f.u8(name).enumeration(BSDF2_CODECS).emit()?;
            if let Some(c) = codecs.get_mut(i) {
                *c = codec;
            }
        }
    } else {
        f.ascii("Magic", 8).emit()?;
    }
    let ctrl = f
        .u64("Control block length")
        .check(|&v| (v >> 63 != 0).then(|| Diagnostic::malformed("negative length")))
        .emit()?;
    let diff = f
        .u64("Diff block length")
        .check(|&v| (v >> 63 != 0).then(|| Diagnostic::malformed("negative length")))
        .emit()?;
    let new = f.u64("New file size").emit()?;
    let header = 32u64;
    let ctrl_span = file.sub(header, ctrl);
    let diff_span = file.sub(header.saturating_add(ctrl), diff);
    let extra_span = file.tail(header.saturating_add(ctrl).saturating_add(diff));
    for (i, (name, span)) in [
        ("Control block", ctrl_span),
        ("Diff block", diff_span),
        ("Extra block", extra_span),
    ]
    .into_iter()
    .enumerate()
    {
        let node = if codecs.get(i) == Some(&0) {
            if i == 0 {
                Node::new(name)
                    .span(span)
                    .summary(format!("{} triples", span.len / 24))
                    .lazy(bsdiff_control, span)
            } else {
                Node::new(name).span(span).summary(size(span.len))
            }
        } else {
            embedded(name, input.nested(span)).summary(size(span.len))
        };
        cx.emit(node);
    }
    let codec =
        lookup(BSDF2_CODECS, codecs.first().copied().unwrap_or(1).into()).unwrap_or("unknown");
    cx.annotate(format!(
        "{}, new file {}, control/diff/extra {}/{}/{} bytes ({codec})",
        if bsdf2 {
            "BSDF2 patch"
        } else {
            "bsdiff 4.0 patch"
        },
        size(new),
        ctrl,
        diff,
        extra_span.len
    ));
    Ok(())
}

/// Uncompressed control block: (add, copy, seek) triples.
async fn bsdiff_control(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / 24;
    cx.set_count(crate::node::Count::Exact(count));
    for i in 0..count {
        let entry = span.sub(i.saturating_mul(24), 24);
        let data = cx.read(entry).await?;
        let [add, copy, seek] = [0usize, 8, 16].map(|at| offtin(u64_le(&data, at).unwrap_or(0)));
        cx.push(
            Node::new(format!("Triple {i}"))
                .span(entry)
                .summary(format!(
                    "add {add} bytes, insert {copy} bytes, seek {seek:+}"
                )),
        )
        .await;
    }
    Ok(())
}

async fn bsdiff43(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 16).emit()?;
    let new = f.u64("New file size").emit()?;
    cx.emit(embedded(
        "Interleaved control/diff/extra (bzip2)",
        input.nested(file.tail(24)),
    ));
    cx.annotate(format!(
        "bsdiff 4.3 (Endsley) patch, new file {}",
        size(new)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// PPF (PlayStation Patch Format) 1.0, 2.0, 3.0

declare_format!(pub PPF = "ppf", "PlayStation Patch Format", ["ppf"],
    "application/x-ppf-patch", Probe::Magic(&[(0, b"PPF10"), (0, b"PPF20"), (0, b"PPF30")]), ppf);

const PPF_IMAGE: EnumTable = &[(0, "BIN"), (1, "GI (PrimoDVD)")];

async fn ppf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 60)).await?;
    let version = head
        .data
        .get(3)
        .copied()
        .unwrap_or(b'1')
        .saturating_sub(b'0');
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 5).emit()?;
    f.u8("Encoding")
        .desc("0 = PPF1, 1 = PPF2, 2 = PPF3")
        .emit()?;
    let description = f.ascii("Description", 50).emit()?;
    let mut at = 56u64;
    let mut undo = false;
    if version == 2 {
        let tail = cx.block(file.sub(56, 4)).await?;
        Fields::emitting(&cx, &tail, LE)
            .u32("Input file size")
            .emit()?;
        cx.emit(
            Node::new("Validation block")
                .span(file.sub(60, 1024))
                .desc("1024 bytes of the image at 0x9320"),
        );
        at = 60 + 1024;
    } else if version == 3 {
        let tail = cx.block(file.sub(56, 4)).await?;
        let mut g = Fields::emitting(&cx, &tail, LE);
        g.u8("Image type").enumeration(PPF_IMAGE).emit()?;
        let blockcheck = g
            .u8("Block check")
            .enumeration(&[(0, "disabled"), (1, "enabled")])
            .emit()?
            != 0;
        undo = g
            .u8("Undo data")
            .enumeration(&[(0, "absent"), (1, "present")])
            .emit()?
            != 0;
        g.u8("Reserved").emit()?;
        at = 60;
        if blockcheck {
            cx.emit(
                Node::new("Validation block")
                    .span(file.sub(60, 1024))
                    .desc("1024 bytes of the image at 0x9320 (BIN) or 0x80A0 (GI)"),
            );
            at = 60 + 1024;
        }
    }
    // An optional FILE_ID.DIZ trails the records.
    let mut end = file.len;
    let len_size = if version == 2 { 4u64 } else { 2 };
    if version >= 2 && file.len > 34 {
        let marker_at = file.len.saturating_sub(16u64.saturating_add(len_size));
        if cx.read_avail(file.sub(marker_at, 16)).await? == b"@END_FILE_ID.DIZ" {
            let raw = cx
                .read(file.sub(marker_at.saturating_add(16), len_size))
                .await?;
            let len = if len_size == 4 {
                u64::from(u32_le(&raw, 0).unwrap_or(0))
            } else {
                u64::from(u16_le(&raw, 0).unwrap_or(0))
            };
            let begin = marker_at.saturating_sub(len).saturating_sub(18);
            if cx.read_avail(file.sub(begin, 18)).await? == b"@BEGIN_FILE_ID.DIZ" {
                end = begin;
                let span = file.sub(begin.saturating_add(18), len);
                let diz = cx.read_avail(span.sub(0, 4096)).await?;
                cx.emit(
                    Node::new("FILE_ID.DIZ")
                        .span(file.tail(begin))
                        .value(text(String::from_utf8_lossy(&diz).trim_end().to_owned())),
                );
            }
        }
    }
    let offset_size = if version == 3 { 8u64 } else { 4 };
    let mut cur = Cursor::new(&cx, file.sub(0, end), LE);
    cur.seek(at);
    let (mut records, mut bytes) = (0u64, 0u64);
    while cur.remaining() > offset_size {
        let start = cur.pos();
        let offset = if version == 3 {
            cur.u64().await?
        } else {
            u64::from(cur.u32().await?)
        };
        let len = cur.u8().await?;
        let data = cur.span(len.into());
        cur.skip(len.into());
        let mut node = Node::new(format!("Record {}", records.saturating_add(1)))
            .value(hex(offset, 64))
            .summary(format!("{len} bytes at {offset:#x}"));
        if undo {
            node = node.summary(format!("{len} bytes at {offset:#x}, with undo data"));
            cur.skip(len.into());
        }
        node = node.span(cur.since(start)).target(data);
        records = records.saturating_add(1);
        bytes = bytes.saturating_add(len.into());
        cx.push(node).await;
    }
    cx.annotate(format!(
        "PPF {version}.0 patch {:?}, {records} records, {bytes} bytes{}",
        description.trim(),
        if undo { ", undo data" } else { "" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// APS (N64 and GBA variants)

declare_format!(pub APS_N64 = "aps-n64", "APS patch (Nintendo 64)", ["aps"],
    "application/x-aps-patch", Probe::Magic(&[(0, b"APS10")]), aps_n64);

fn aps_gba_probe(h: &Head<'_>) -> bool {
    h.at(0, b"APS1")
        && !h.at(0, b"APS10")
        && h.len >= 12
        && h.len.saturating_sub(12).is_multiple_of(65544)
}

declare_format!(pub APS_GBA = "aps-gba", "APS patch (Game Boy Advance)", ["aps"],
    "application/x-aps-patch", Probe::Custom(aps_gba_probe), aps_gba);

const APS_MODES: EnumTable = &[(0, "simple"), (1, "N64-specific")];
const APS_N64_FORMAT: EnumTable = &[(0, "Doctor V64 (byte-swapped)"), (1, "big-endian (.z64)")];

async fn aps_n64(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 78)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 5).emit()?;
    let mode = f.u8("Header type").enumeration(APS_MODES).emit()?;
    f.u8("Encoding method").emit()?;
    let description = f.ascii("Description", 50).emit()?;
    let mut cart = String::new();
    if mode == 1 {
        f.u8("Original image format")
            .enumeration(APS_N64_FORMAT)
            .emit()?;
        cart = f.ascii("Cartridge ID", 3).emit()?;
        f.bytes("CRC", 8).emit()?;
        f.bytes("Padding", 5).emit()?;
    }
    let out = f.u32("Output size").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(f.pos());
    let mut records = 0u64;
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let offset = cur.u32().await?;
        let len = cur.u8().await?;
        let summary = if len == 0 {
            let value = cur.u8().await?;
            let run = cur.u8().await?;
            format!("{run} × {value:#04x} at {offset:#x} (RLE)")
        } else {
            cur.skip(len.into());
            format!("{len} bytes at {offset:#x}")
        };
        records = records.saturating_add(1);
        cx.push(
            Node::new(format!("Record {records}"))
                .span(cur.since(start))
                .value(hex(offset.into(), 32))
                .summary(summary),
        )
        .await;
    }
    cx.annotate(format!(
        "APS N64 patch {:?}{}, {records} records, output {}",
        description.trim(),
        if cart.is_empty() {
            String::new()
        } else {
            format!(" for cart {cart}")
        },
        size(out.into())
    ));
    Ok(())
}

record! {
    pub struct ApsGbaHeader {
        magic: ascii[4] "Magic",
        source: u32 "Source size",
        target: u32 "Target size",
    }
}

const APS_GBA_BLOCK: u64 = 0x10000;

async fn aps_gba(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: ApsGbaHeader = emit_record(&cx, file.sub(0, ApsGbaHeader::SIZE), LE).await?;
    let record = APS_GBA_BLOCK.saturating_add(8);
    let count = file.len.saturating_sub(12) / (APS_GBA_BLOCK + 8);
    cx.set_count(crate::node::Count::Exact(count.saturating_add(3)));
    for i in 0..count {
        let span = file.sub(12u64.saturating_add(i.saturating_mul(record)), record);
        let head = cx.read(span.sub(0, 8)).await?;
        let offset = u32_le(&head, 0).unwrap_or(0);
        cx.push(
            Node::new(format!("Block {i}"))
                .span(span)
                .value(hex(offset.into(), 32))
                .summary(format!(
                    "64 KiB XOR at {offset:#x}, CRC16 {:#06x} → {:#06x}",
                    u16_le(&head, 4).unwrap_or(0),
                    u16_le(&head, 6).unwrap_or(0)
                ))
                .lazy(aps_gba_block, span),
        )
        .await;
    }
    cx.annotate(format!(
        "APS GBA patch, {} → {}, {count} blocks",
        size(h.source.into()),
        size(h.target.into())
    ));
    Ok(())
}

async fn aps_gba_block(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Offset").hex().emit()?;
    f.u16("Source CRC-16").hex().emit()?;
    f.u16("Target CRC-16").hex().emit()?;
    cx.emit(Node::new("XOR data").span(span.tail(8)));
    Ok(())
}

// ---------------------------------------------------------------------------
// GDIFF (W3C generic diff)

declare_format!(pub GDIFF = "gdiff", "Generic Diff Format (GDIFF)", ["gdiff", "gdf"],
    "application/gdiff", Probe::Magic(&[(0, b"\xd1\xff\xd1\xff\x04")]), gdiff);

async fn gdiff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(hex(0xd1ff_d1ff, 32)),
    );
    cx.emit(Node::new("Version").span(file.sub(4, 1)).value(dec(4, 8)));
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(5);
    let (mut commands, mut out, mut data, mut copies) = (0u64, 0u64, 0u64, 0u64);
    let mut ended = false;
    while !cur.at_end() {
        let start = cur.pos();
        let op = cur.u8().await?;
        let (name, len, summary) = match op {
            0 => {
                ended = true;
                ("EOF", 0, "end of patch".to_owned())
            }
            1..=248 => {
                let len = match op {
                    247 => u64::from(cur.u16().await?),
                    248 => u64::from(cur.u32().await?),
                    n => u64::from(n),
                };
                cur.skip(len);
                data = data.saturating_add(len);
                ("DATA", len, format!("{len} literal bytes"))
            }
            _ => {
                let pos = match op {
                    249..=251 => u64::from(cur.u16().await?),
                    252..=254 => u64::from(cur.u32().await?),
                    _ => cur.u64().await?,
                };
                let len = match op {
                    249 | 252 => u64::from(cur.u8().await?),
                    250 | 253 => u64::from(cur.u16().await?),
                    _ => u64::from(cur.u32().await?),
                };
                copies = copies.saturating_add(1);
                ("COPY", len, format!("{len} bytes from {pos:#x}"))
            }
        };
        commands = commands.saturating_add(1);
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .value(hex(out, 64))
                .summary(format!("opcode {op}: {summary}")),
        )
        .await;
        out = out.saturating_add(len);
        if ended {
            break;
        }
    }
    if !ended {
        cx.diag(Diagnostic::warning("no EOF command"));
    }
    cx.annotate(format!(
        "GDIFF, {commands} commands ({copies} copies, {data} literal bytes), output {out} bytes"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows delta compression (MSDelta PA30)

declare_format!(pub MSDELTA = "msdelta", "Windows delta patch (PA30)", ["delta", "pa30"],
    "application/x-msdelta", Probe::Magic(&[(0, b"PA30")]), msdelta);

async fn msdelta(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    f.u64("Target file time").filetime().emit()?;
    cx.emit(
        Node::new("Bit-packed header and delta")
            .span(file.tail(12))
            .diag(Diagnostic::unsupported("MSDelta bitstream")),
    );
    cx.annotate(format!(
        "Windows delta patch (PA30), {} of delta",
        size(file.len.saturating_sub(12))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Ninja 2 (RUP)

declare_format!(pub RUP = "rup", "Ninja patch (RUP)", ["rup"],
    "application/x-rup-patch", Probe::Magic(&[(0, b"NINJA2")]), rup);

const RUP_ROM_TYPES: EnumTable = &[
    (0, "raw"),
    (1, "NES"),
    (2, "Famicom Disk System"),
    (3, "SNES"),
    (4, "Nintendo 64"),
    (5, "Game Boy"),
    (6, "Master System"),
    (7, "Mega Drive"),
    (8, "PC Engine"),
    (9, "Lynx"),
];

record! {
    pub struct RupHeader {
        magic: ascii[6] "Magic",
        encoding: u8 "Text encoding" .enumeration(&[(0, "ISO-8859-1"), (1, "Shift-JIS")]),
        author: ascii[84] "Author",
        version: ascii[11] "Version",
        title: ascii[256] "Title",
        genre: ascii[26] "Genre",
        language: ascii[26] "Language",
        date: ascii[8] "Date (YYYYMMDD)",
        website: ascii[512] "Website",
        description: ascii[1074] "Description",
    }
}

/// RUP's variable-length value: a byte count, then that many bytes (LE).
async fn rup_vlv(cur: &mut Cursor<'_>) -> Result<u64> {
    let n = cur.u8().await?;
    if n > 8 {
        return Err(
            Diagnostic::malformed(format!("{n}-byte variable-length value")).at(cur.span(0)),
        );
    }
    let raw = cur.bytes(n.into()).await?;
    Ok(raw
        .iter()
        .rev()
        .fold(0u64, |acc, &b| acc << 8 | u64::from(b)))
}

async fn rup(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: RupHeader = emit_record(&cx, file.sub(0, RupHeader::SIZE), LE).await?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(0x800);
    let (mut files, mut records, mut bytes) = (0u32, 0u64, 0u64);
    while !cur.at_end() {
        let start = cur.pos();
        match cur.u8().await? {
            0 => {
                cx.push(Node::new("End").span(cur.since(start))).await;
                break;
            }
            1 => {
                let name_len = rup_vlv(&mut cur).await?;
                let name =
                    String::from_utf8_lossy(&cur.bytes(name_len.min(4096)).await?).into_owned();
                let kind = cur.u8().await?;
                let source = rup_vlv(&mut cur).await?;
                let target = rup_vlv(&mut cur).await?;
                cur.skip(32);
                let mut overflow = String::new();
                if source != target {
                    let mode = cur.u8().await?;
                    let len = rup_vlv(&mut cur).await?;
                    cur.skip(len);
                    overflow = format!(
                        ", {} {len} bytes",
                        if mode == b'A' {
                            "appends"
                        } else {
                            "minifies by"
                        }
                    );
                }
                files = files.saturating_add(1);
                cx.push(
                    Node::new(format!("Open file {name:?}"))
                        .span(cur.since(start))
                        .value(Value::Enum {
                            raw: kind.into(),
                            bits: 8,
                            name: lookup(RUP_ROM_TYPES, kind.into()),
                        })
                        .summary(format!("{} → {}{overflow}", size(source), size(target))),
                )
                .await;
            }
            2 => {
                let offset = rup_vlv(&mut cur).await?;
                let len = rup_vlv(&mut cur).await?;
                let data = cur.span(len);
                cur.skip(len);
                records = records.saturating_add(1);
                bytes = bytes.saturating_add(len);
                cx.push(
                    Node::new("XOR record")
                        .span(cur.since(start))
                        .value(hex(offset, 64))
                        .summary(format!("{len} bytes at {offset:#x}"))
                        .target(data),
                )
                .await;
            }
            other => {
                cx.push(
                    Node::new("Unknown command")
                        .span(cur.since(start))
                        .value(hex(other.into(), 8))
                        .diag(Diagnostic::malformed("unknown RUP command")),
                )
                .await;
                break;
            }
        }
    }
    cx.annotate(format!(
        "Ninja RUP patch {:?} v{} by {}, {files} file(s), {records} XOR records ({bytes} bytes)",
        h.title.trim(),
        h.version.trim(),
        h.author.trim()
    ));
    Ok(())
}
