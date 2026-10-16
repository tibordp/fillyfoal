//! zlib streams (RFC 1950) as files: `.zlib`, `.zz` (`pigz -z`, Python's
//! `zlib.compress`, `qpdf --decode`-style dumps, raw compressed blobs).
//!
//! A two-byte header (CMF: the method, 8 for DEFLATE, and the window size;
//! FLG: a check making `CMF * 256 + FLG` a multiple of 31, a preset
//! dictionary flag and the compression level), the DEFLATE data, and the
//! Adler-32 of the decompressed data, big-endian.
//!
//! The header alone is far too weak a signature: about one 16-bit value in
//! a thousand passes its checks, text included (`HK`, `x^`). So the probe
//! also inflates what the head holds: a file the head holds whole must be
//! exactly one complete stream whose Adler-32 matches; a longer one must
//! inflate without error up to the end of the head (at least 4 KiB of it),
//! or end inside it with a matching Adler-32. Random and text data fail
//! that within a few hundred bytes. Streams with a preset
//! dictionary cannot be inflated without it: a second-phase probe takes
//! them by their header and a `.zlib` or `.zz` name, and they are listed
//! (header, dictionary id, data, trailer) without being decoded.
//!
//! Small files are decoded when the node is expanded, to find where the
//! stream ends and check its Adler-32 (damage found then is reported on
//! the compressed data); the content of larger ones is decoded on demand,
//! and their trailer checked when expanded.

use crate::codec::Adler32;
use crate::codec::pipeline::{Status, Step};
use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{enumv, hex, uint};
use crate::formats::{Codec, Format, HEAD_LEN, Head, Input, Probe, content};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "zlib",
    title: "zlib compressed data",
    extensions: &["zlib", "zz"],
    mime: "application/zlib",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Streams with a preset dictionary, which the first-phase probe cannot
/// inflate: a header with the dictionary flag (checked as for any stream)
/// and a `.zlib` or `.zz` name.
pub static DICT_DEEP: crate::formats::DeepProbe = crate::formats::DeepProbe {
    format: &FORMAT,
    tail: false,
    over: &[],
    probe: |d| {
        let (Some(&cmf), Some(&flg)) = (d.head.data.first(), d.head.data.get(1)) else {
            return false;
        };
        flg & 0x20 != 0
            && header_ok(cmf, flg, true)
            && d.head.len >= 10
            && (d.extension_is("zlib") || d.extension_is("zz"))
    },
};

const LEVELS: EnumTable = &[(0, "fastest"), (1, "fast"), (2, "default"), (3, "maximum")];
/// Input a probe must inflate without error when the head does not hold
/// the whole file.
const PROBE_INPUT: usize = 4096;
/// Output per inflate step in the probe: a stored block is copied a step
/// at a time, so running out of input shows this close to the end.
const PROBE_STEP: usize = 1024;
/// An error this close to the end of the head is the head running out.
const PROBE_MARGIN: usize = 2 * PROBE_STEP;
/// Output a probe may produce before taking the stream as valid.
const PROBE_OUTPUT: usize = 1 << 20;
/// Files up to this size are decoded when expanded.
const EAGER_LEN: u64 = 1 << 20;
/// Output an eager decode produces at most.
const EAGER_OUTPUT: u64 = 16 << 20;
const CHUNK: u64 = 64 * 1024;
const STEP: usize = 64 * 1024;

/// Whether `cmf`, `flg` pass the header checks (DEFLATE, a window of at
/// most 32 KiB, the check, no preset dictionary when `dict` is false).
fn header_ok(cmf: u8, flg: u8, dict: bool) -> bool {
    cmf & 0x0f == 8
        && cmf >> 4 <= 7
        && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0
        && (dict || flg & 0x20 == 0)
}

fn probe(h: &Head) -> bool {
    let (Some(&cmf), Some(&flg)) = (h.data.first(), h.data.get(1)) else {
        return false;
    };
    if !header_ok(cmf, flg, false) || h.len < 8 {
        return false;
    }
    let held = crate::bytes::to_u64(h.data.len());
    let whole = if h.len_known {
        held == h.len
    } else {
        held < HEAD_LEN
    };
    if !whole && h.data.len() < PROBE_INPUT {
        return false;
    }
    // Inflate the head directly: an error near its end is the head running
    // out (accepted for a file longer than the head), anywhere else it is
    // not DEFLATE.
    let body = h.data.get(2..).unwrap_or_default();
    let mut inflate = crate::codec::inflate::Inflate::new();
    let mut out = Vec::new();
    loop {
        match inflate.step(body, &mut out, PROBE_STEP, PROBE_OUTPUT) {
            Ok(Step::More) => {}
            Ok(Step::Done) => {
                // One whole stream with its checksum, ending the file (or
                // what the head holds of a longer file).
                let end = inflate.consumed();
                let matches = crate::bytes::u32_be(body, end)
                    .is_some_and(|t| t == crate::codec::adler32(&out));
                return matches && (!whole || end.saturating_add(4) == body.len());
            }
            Err(e) if e.kind == DiagKind::Limit => return true,
            Err(_) => {
                return !whole && inflate.consumed().saturating_add(PROBE_MARGIN) >= body.len();
            }
        }
    }
}

/// What decoding the stream found.
struct Walk {
    /// Where the Adler-32 starts.
    trailer: u64,
    decoded: u64,
    adler: u32,
}

/// Decodes the stream from the start (at most `budget` bytes of output),
/// a bounded step at a time; `None` past the budget.
async fn walk(cx: &Cx, file: Span, budget: u64) -> Result<Option<Walk>> {
    let mut decoder = Codec::Deflate
        .decoder()
        .ok_or_else(|| Diagnostic::unsupported("DEFLATE"))?;
    let body = 2u64;
    let mut input = Vec::new();
    let mut in_base = body;
    let mut eof = false;
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut adler = Adler32::new();
    let mut decoded = 0u64;
    loop {
        let status = decoder
            .decode(&input, eof, &mut out, STEP, usize::MAX)
            .map_err(|e| e.at(file.tail(body)))?;
        let fresh = out.get(seen..).unwrap_or_default();
        adler.update(fresh);
        decoded = decoded.saturating_add(crate::bytes::to_u64(fresh.len()));
        cx.charge(crate::bytes::to_u64(fresh.len()) >> 12).await;
        let n = decoder.releasable_output(out.len()).min(out.len());
        out.drain(..n);
        decoder.release_output(n);
        seen = out.len();
        let n = decoder.releasable_input().min(input.len());
        input.drain(..n);
        decoder.release_input(n);
        in_base = in_base.saturating_add(crate::bytes::to_u64(n));
        match status {
            Status::Done => break,
            Status::More => {
                cx.checkpoint().await;
                if decoded > budget {
                    return Ok(None);
                }
            }
            Status::NeedInput => {
                if eof {
                    return Err(Diagnostic::new(
                        DiagKind::Truncated,
                        "the DEFLATE data ends early",
                    )
                    .at(file.tail(body)));
                }
                let at = in_base.saturating_add(crate::bytes::to_u64(input.len()));
                cx.progress_in(file, at);
                let data = cx.read_avail(file.sub(at, CHUNK)).await?;
                eof = data.is_empty();
                input.extend_from_slice(&data);
            }
        }
    }
    Ok(Some(Walk {
        trailer: in_base.saturating_add(crate::bytes::to_u64(decoder.consumed())),
        decoded,
        adler: adler.value(),
    }))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let raw = cx.read(file.sub(0, 2)).await?;
    let (cmf, flg) = (
        raw.first().copied().unwrap_or(0),
        raw.get(1).copied().unwrap_or(0),
    );
    let dict = flg & 0x20 != 0;
    let window = 1u64 << (cmf >> 4).min(7).saturating_add(8);
    let level = flg >> 6;
    let mut header = Node::new("Header")
        .span(file.sub(0, 2))
        .summary(format!(
            "DEFLATE, {} window, {} level",
            size(window),
            crate::formats::util::val::name_or(LEVELS, level.into(), "")
        ))
        .lazy(header_fields, (file, cmf, flg));
    if !header_ok(cmf, flg, true) {
        header = header.diag(Diagnostic::malformed("not a zlib header"));
    }
    cx.emit(header);
    let data_at = 2u64;
    if dict {
        let span = file.sub(2, 4);
        let id = crate::bytes::u32_be(&cx.read(span).await?, 0).unwrap_or(0);
        cx.emit(
            Node::new("Dictionary id")
                .span(span)
                .value(hex(id, 32))
                .desc("Adler-32 of the preset dictionary"),
        );
        cx.annotate(format!(
            "zlib, {} window, preset dictionary {id:#010x}",
            size(window)
        ));
        let data = file.sub(6, file.len.saturating_sub(10));
        cx.emit(
            Node::new("Compressed data")
                .span(data)
                .summary(size(data.len))
                .diag(Diagnostic::unsupported(
                    "decoding needs the preset dictionary, which is not in the file",
                )),
        );
        let trailer = file.tail(file.len.saturating_sub(4).max(6));
        let recorded = cx.read_avail(trailer).await?;
        let mut node = Node::new("Adler-32")
            .span(trailer)
            .desc("Of the decompressed data; not checked");
        if let Some(v) = crate::bytes::u32_be(&recorded, 0) {
            node = node.value(hex(v, 32));
        }
        cx.emit(node);
        return Ok(());
    }
    // A small stream is decoded now; its damage is shown on the data.
    let (walked, damage) = if file.len <= EAGER_LEN {
        match walk(&cx, file, EAGER_OUTPUT).await {
            Ok(w) => (w, None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };
    let mut summary = format!(
        "zlib, {} window, {} level",
        size(window),
        crate::formats::util::val::name_or(LEVELS, level.into(), "")
    );
    match &walked {
        Some(w) => {
            summary = format!("{summary}, {} uncompressed", plural(w.decoded, "byte"));
            cx.emit(content(
                "Decompressed",
                input,
                file,
                Codec::Zlib,
                Some(w.decoded),
            ));
            cx.emit(
                Node::new("Compressed data")
                    .span(file.sub(data_at, w.trailer.saturating_sub(data_at)))
                    .summary(size(w.trailer.saturating_sub(data_at))),
            );
            let span = file.sub(w.trailer, 4);
            cx.emit(checked(span, &cx.read_avail(span).await?, w));
            let end = w.trailer.saturating_add(4);
            if end < file.len {
                let rest = file.tail(end);
                cx.emit(
                    Node::new("Trailing data")
                        .span(rest)
                        .summary(size(rest.len))
                        .diag(
                            Diagnostic::warning(format!(
                                "{} after the stream",
                                plural(rest.len, "byte")
                            ))
                            .at(rest),
                        ),
                );
            }
        }
        None => {
            cx.emit(content("Decompressed", input, file, Codec::Zlib, None));
            let trailer = file.tail(file.len.saturating_sub(4));
            let mut data = Node::new("Compressed data")
                .span(
                    file.sub(
                        data_at,
                        trailer
                            .offset
                            .saturating_sub(file.offset)
                            .saturating_sub(data_at),
                    ),
                )
                .summary(size(file.len.saturating_sub(data_at).saturating_sub(4)));
            if let Some(e) = damage {
                data = data.diag(e);
            }
            cx.emit(data);
            let recorded = cx.read_avail(trailer).await?;
            let mut node = Node::new("Adler-32")
                .span(trailer)
                .desc("Of the decompressed data; checked when expanded (decodes the whole stream)")
                .lazy(check, file);
            if let Some(v) = crate::bytes::u32_be(&recorded, 0) {
                node = node.value(hex(v, 32));
            }
            cx.emit(node);
        }
    }
    cx.annotate(summary);
    Ok(())
}

/// The trailer at `span` (`recorded` its bytes), checked against the walk.
fn checked(span: Span, recorded: &[u8], w: &Walk) -> Node {
    let mut node = Node::new("Adler-32")
        .span(span)
        .desc("Of the decompressed data");
    match crate::bytes::u32_be(recorded, 0) {
        Some(v) => {
            node = node.value(hex(v, 32));
            if v != w.adler {
                node = node.diag(Diagnostic::warning(format!(
                    "Adler-32 {v:#010x}; the data decodes to {:#010x}",
                    w.adler
                )));
            }
        }
        None => {
            node = node.diag(Diagnostic::truncated(
                span,
                crate::bytes::to_u64(recorded.len()),
            ));
        }
    }
    node
}

/// Decodes a large stream to its end to check its trailer.
async fn check(cx: Cx, file: Span) -> Result<()> {
    let Some(w) = walk(&cx, file, u64::MAX).await? else {
        return Ok(());
    };
    cx.emit(Node::new("Computed").value(hex(w.adler, 32)));
    cx.emit(
        Node::new("Decompressed size")
            .value(uint(w.decoded, 64))
            .summary(size(w.decoded)),
    );
    let end = w.trailer.saturating_add(4);
    let span = file.sub(w.trailer, 4);
    let node = checked(span, &cx.read_avail(span).await?, &w);
    let mut node = node.renamed("Stream trailer");
    if end != file.len {
        node = node.diag(Diagnostic::warning(format!(
            "the stream ends at {end:#x}, {} before the end of the file",
            plural(file.len.saturating_sub(end), "byte")
        )));
    }
    cx.emit(node);
    Ok(())
}

async fn header_fields(cx: Cx, (file, cmf, flg): (Span, u8, u8)) -> Result<()> {
    let cmf_span = file.sub(0, 1);
    let flg_span = file.sub(1, 1);
    cx.emit(Node::new("CMF").span(cmf_span).value(hex(cmf, 8)));
    cx.emit(
        Node::new("Method")
            .span(cmf_span)
            .value(uint(cmf & 0x0f, 4))
            .summary(if cmf & 0x0f == 8 {
                "DEFLATE"
            } else {
                "unknown"
            }),
    );
    let cinfo = cmf >> 4;
    let mut info = Node::new("Window (CINFO)")
        .span(cmf_span)
        .value(uint(cinfo, 4));
    if cinfo <= 7 {
        info = info.summary(size(1u64 << cinfo.saturating_add(8)));
    } else {
        info = info.diag(Diagnostic::malformed("window larger than 32 KiB"));
    }
    cx.emit(info);
    cx.emit(Node::new("FLG").span(flg_span).value(hex(flg, 8)));
    let mut check = Node::new("Check (FCHECK)")
        .span(flg_span)
        .value(uint(flg & 0x1f, 5));
    if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        check = check.diag(Diagnostic::malformed(
            "CMF * 256 + FLG is not a multiple of 31",
        ));
    }
    cx.emit(check);
    cx.emit(
        Node::new("Preset dictionary (FDICT)")
            .span(flg_span)
            .value(uint(flg >> 5 & 1, 1)),
    );
    cx.emit(
        Node::new("Level (FLEVEL)")
            .span(flg_span)
            .value(enumv(flg >> 6, 2, LEVELS)),
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn head(data: &[u8]) -> bool {
        probe(&Head {
            data,
            tail: data,
            len: data.len() as u64,
            len_known: true,
        })
    }

    /// `printf 'hello zlib' | python3 -c 'import sys, zlib;
    /// sys.stdout.buffer.write(zlib.compress(sys.stdin.buffer.read()))'`
    const HELLO: &[u8] = &[
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xa8, 0xca, 0xc9, 0x4c, 0x02, 0x00, 0x15,
        0x95, 0x03, 0xe6,
    ];

    #[test]
    fn probe_checks_the_whole_stream() {
        assert!(head(HELLO));
        let mut bad = HELLO.to_vec();
        bad[17] ^= 1;
        assert!(!head(&bad));
        let mut longer = HELLO.to_vec();
        longer.push(0);
        assert!(!head(&longer));
        assert!(!head(b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Fillyfoal\n"));
        assert!(!head(b"x^2 + y^2 = r^2\n"));
    }
}
