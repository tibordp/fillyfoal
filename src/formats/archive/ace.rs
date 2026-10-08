//! ACE and SEA ARC archives.
//!
//! ACE: blocks with a CRC-16, size, type and flags; the main header carries
//! the `**ACE**` signature, file headers carry sizes, attributes, CRC-32 and
//! the compression type, followed by the packed data. ACE 1.0 LZ77 and ACE
//! 2.0 "blocked" data (with its EXE, DELTA, SOUND and PIC modes) are
//! decompressed by [`crate::codec::ace`]; a solid archive is decoded once,
//! lazily, as one stream whose spans are its files' contents; comments are
//! decoded. The layout and the
//! codecs follow `acefile` (a reimplementation of `unace`); there is no
//! published specification. Blowfish-encrypted files are not decrypted.
//!
//! ARC: a chain of `0x1A`-prefixed headers (method, 13-byte name, sizes,
//! DOS time, CRC-16), ending with method 0.
//!
//! Stored members are dissected in place; the ARC RLE/Huffman/LZW methods
//! are unsupported leaves.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::codec::{Codec, crc32};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{ByteReader, count, emit_nodes, hex, human_size, unsupported};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const MAX_ENTRIES: u64 = 1 << 20;

pub static ACE: Format = Format {
    name: "ace",
    title: "ACE archive",
    extensions: &["ace", "cba"],
    mime: "application/x-ace-compressed",
    probe: Probe::Magic(&[(7, b"**ACE**")]),
    dissect: crate::expander!(dissect_ace: Input),
};

pub static ARC: Format = Format {
    name: "arc",
    title: "ARC archive (SEA)",
    extensions: &["arc", "ark", "pak"],
    mime: "application/x-arc",
    probe: Probe::Custom(probe_arc),
    dissect: crate::expander!(dissect_arc: Input),
};

// ---------------------------------------------------------------------------
// ACE

const ACE_TYPE: EnumTable = &[
    (0, "main header"),
    (1, "file (32-bit sizes)"),
    (2, "recovery record (32-bit)"),
    (3, "file (64-bit sizes)"),
    (4, "recovery record (64-bit, A)"),
    (5, "recovery record (64-bit, B)"),
];

const ACE_FILE_FLAGS: FlagTable = &[
    flag(0x0001, "ADDSIZE"),
    flag(0x0002, "COMMENT"),
    flag(0x0004, "64BIT"),
    flag(0x0400, "NTSECURITY"),
    flag(0x1000, "CONTPREV"),
    flag(0x2000, "CONTNEXT"),
    flag(0x4000, "PASSWORD"),
    flag(0x8000, "SOLID"),
];

const ACE_MAIN_FLAGS: FlagTable = &[
    flag(0x0001, "ADDSIZE"),
    flag(0x0002, "COMMENT"),
    flag(0x0100, "V20FORMAT"),
    flag(0x0200, "SFX"),
    flag(0x0400, "LIMITSFXJR"),
    flag(0x0800, "MULTIVOLUME"),
    flag(0x1000, "ADVERT"),
    flag(0x2000, "RECOVERY"),
    flag(0x4000, "LOCKED"),
    flag(0x8000, "SOLID"),
];

const ACE_RECOVERY_FLAGS: FlagTable = &[flag(0x0001, "ADDSIZE"), flag(0x0004, "64BIT")];

const ACE_HOST: EnumTable = &[
    (0, "MS-DOS"),
    (1, "OS/2"),
    (2, "Win32"),
    (3, "Unix"),
    (4, "Mac OS"),
    (5, "Win NT"),
    (6, "Primos"),
    (7, "Apple GS"),
    (8, "Atari"),
    (9, "VAX VMS"),
    (10, "Amiga"),
    (11, "NeXT"),
    (12, "Linux"),
];

const ACE_COMP: EnumTable = &[(0, "stored"), (1, "LZ77"), (2, "blocked")];

const ACE_QUALITY: EnumTable = &[
    (0, "store"),
    (1, "fastest"),
    (2, "fast"),
    (3, "normal"),
    (4, "good"),
    (5, "best"),
];

const ACE_ATTRIBUTES: FlagTable = &[
    flag(0x0001, "READONLY"),
    flag(0x0002, "HIDDEN"),
    flag(0x0004, "SYSTEM"),
    flag(0x0008, "VOLUME_ID"),
    flag(0x0010, "DIRECTORY"),
    flag(0x0020, "ARCHIVE"),
    flag(0x0040, "DEVICE"),
    flag(0x0080, "NORMAL"),
    flag(0x0100, "TEMPORARY"),
    flag(0x0200, "SPARSE_FILE"),
    flag(0x0400, "REPARSE_POINT"),
    flag(0x0800, "COMPRESSED"),
    flag(0x1000, "OFFLINE"),
    flag(0x2000, "NOT_CONTENT_INDEXED"),
    flag(0x4000, "ENCRYPTED"),
];

const ACE_FLAG_COMMENT: u16 = 0x0002;
const ACE_FLAG_NTSECURITY: u16 = 0x0400;
const ACE_FLAG_ADVERT: u16 = 0x1000;
const ACE_FLAG_SPLIT: u16 = 0x3000;
const ACE_FLAG_PASSWORD: u16 = 0x4000;
const ACE_FLAG_SOLID: u16 = 0x8000;
const ACE_FLAG_V20: u16 = 0x0100;

/// ACE's header CRC: CRC-32 without the final inversion, low 16 bits.
fn ace_crc(data: &[u8]) -> u16 {
    u16::try_from(!crc32(data) & 0xffff).unwrap_or(0)
}

/// A block as the listing sees it.
struct AceBlock {
    kind: u8,
    flags: u16,
    /// The data after the header (`ADDSIZE`).
    packed: u64,
    original: u64,
    header_span: Span,
    span: Span,
    crc_ok: bool,
}

async fn ace_block_at(cx: &Cx, file: Span, at: u64) -> Result<AceBlock> {
    let head = cx.read(file.sub(at, 4)).await?;
    let size = u64::from(u16_le(&head, 2).unwrap_or(0));
    let header_span = file.sub(at, size.saturating_add(4));
    let header = cx.read(header_span).await?;
    let kind = header.get(4).copied().unwrap_or(0);
    let flags = u16_le(&header, 5).unwrap_or(0);
    let crc_ok = header
        .get(4..)
        .is_some_and(|b| Some(ace_crc(b)) == u16_le(&header, 0));
    let wide = flags & 0x0004 != 0 || kind == 3 || kind == 4 || kind == 5;
    let (packed, original) = if flags & 0x0001 != 0 {
        if wide {
            (
                u64_le(&header, 7).unwrap_or(0),
                u64_le(&header, 15).unwrap_or(0),
            )
        } else {
            (
                u64::from(u32_le(&header, 7).unwrap_or(0)),
                u64::from(u32_le(&header, 11).unwrap_or(0)),
            )
        }
    } else {
        (0, 0)
    };
    // Recovery records have only the one size.
    let original = if kind == 1 || kind == 3 { original } else { 0 };
    Ok(AceBlock {
        kind,
        flags,
        packed,
        original,
        header_span,
        span: file.sub(at, header_span.len.saturating_add(packed)),
        crc_ok,
    })
}

/// What a file header says about its data.
fn ace_member(header: &[u8], block: &AceBlock) -> crate::codec::ace::Member {
    let at = if block.kind == 3 { 23usize } else { 15 };
    crate::codec::ace::Member {
        packed: block.packed,
        size: block.original,
        crc: u32_le(header, at.saturating_add(8)).unwrap_or(0),
        method: header.get(at.saturating_add(12)).copied().unwrap_or(0xff),
    }
}

/// The walker's state, for resume marks: offset, files, total size,
/// blocks seen, and whether the archive is solid / ACE 2.0.
type AceWalk = (u64, u64, u64, u64, bool, bool);

pub async fn dissect_ace(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (mut at, mut files, mut total, mut seen, mut solid, mut v20) =
        cx.resume::<AceWalk>().unwrap_or((0, 0, 0, 0, false, false));
    cx.annotate("ACE archive");
    while at.saturating_add(7) <= file.len && seen < MAX_ENTRIES {
        let walk = (at, files, total, seen, solid, v20);
        cx.mark(move || walk);
        seen = seen.saturating_add(1);
        let block = ace_block_at(&cx, file, at).await?;
        let header = cx.read(block.header_span).await?;
        let (name, summary) = match block.kind {
            0 => {
                solid = block.flags & ACE_FLAG_SOLID != 0;
                v20 = block.flags & ACE_FLAG_V20 != 0 || header.get(14).is_some_and(|&v| v >= 20);
                ("Main header".to_owned(), String::new())
            }
            1 | 3 => {
                let name_at = if block.kind == 3 { 43usize } else { 35 };
                let len = usize::from(u16_le(&header, name_at.saturating_sub(2)).unwrap_or(0));
                let name = header
                    .get(name_at..name_at.saturating_add(len))
                    .unwrap_or_default();
                files = files.saturating_add(1);
                total = total.saturating_add(block.original);
                let m = ace_member(&header, &block);
                let method = crate::value::lookup(ACE_COMP, m.method.into()).unwrap_or("unknown");
                let mut summary = format!("{}, {method}", human_size(block.original));
                if block.flags & ACE_FLAG_PASSWORD != 0 {
                    summary.push_str(", encrypted");
                }
                (String::from_utf8_lossy(name).replace('\\', "/"), summary)
            }
            _ => (
                crate::value::lookup(ACE_TYPE, block.kind.into())
                    .unwrap_or("unknown block")
                    .to_owned(),
                human_size(block.packed),
            ),
        };
        let mut node = Node::new(name)
            .span(block.span)
            .lazy(ace_block, (input, block.span, block.header_span, solid));
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if !block.crc_ok {
            node = node.diag(Diagnostic::warning("header CRC mismatch"));
        }
        cx.progress_in(file, block.span.end());
        cx.push(node).await;
        if block.header_span.len <= 4 {
            break;
        }
        at = at.saturating_add(block.span.len);
    }
    cx.annotate(format!(
        "ACE {} archive{}, {}, {} uncompressed",
        if v20 { "2.0" } else { "1.0" },
        if solid { " (solid)" } else { "" },
        count(files, "file", "files"),
        human_size(total)
    ));
    Ok(())
}

/// Members up to this size are read whole on expansion, so that their
/// CRC-32 is checked (as `expand_content` decodes them eagerly); larger
/// ones are left to be decoded as far as reads reach.
const SOLID_CHECK_LIMIT: u64 = 1024 * 1024;

/// A solid archive's files decoded as one stream, once: each file's
/// content is a span of it.
struct AceSolid {
    stream: Span,
    /// Each file in the stream: the offset of its packed data (in the
    /// archive's source) and of its output (in `stream`), by data offset.
    files: Vec<(u64, u64)>,
    /// The data offset of the first file that cannot be decoded (encrypted
    /// or split); the stream ends before it.
    broken: Option<u64>,
}

/// The solid stream of the archive `file` (walked once, then cached).
async fn ace_solid(cx: &Cx, file: Span) -> Result<Arc<AceSolid>> {
    if let Some(solid) = cx.cached::<AceSolid>(file, "ace solid") {
        return Ok(solid);
    }
    let mut pieces = Vec::new();
    let mut members = Vec::new();
    let mut files = Vec::new();
    let mut total = 0u64;
    let mut broken = None;
    let mut at = 0u64;
    let mut seen = 0u64;
    while at.saturating_add(7) <= file.len && seen < MAX_ENTRIES {
        seen = seen.saturating_add(1);
        let block = ace_block_at(cx, file, at).await?;
        if block.kind == 1 || block.kind == 3 {
            let header = cx.read(block.header_span).await?;
            let d = block.span.tail(block.header_span.len);
            if block.flags & (ACE_FLAG_PASSWORD | ACE_FLAG_SPLIT) != 0 {
                broken = Some(d.offset);
                break;
            }
            let member = ace_member(&header, &block);
            files.push((d.offset, total));
            total = total.saturating_add(member.size);
            pieces.push(d);
            members.push(member);
        }
        if block.header_span.len <= 4 {
            break;
        }
        at = at.saturating_add(block.span.len);
    }
    let data = match pieces.as_slice() {
        [] => return Err(Diagnostic::malformed("no files in the solid stream")),
        [one] => *one,
        [first, .., last] => {
            cx.add_pieces_stepped(
                Origin {
                    parent: Span::new(
                        first.source,
                        first.offset,
                        last.end().saturating_sub(first.offset),
                    ),
                    transform: "ace-solid",
                },
                &pieces,
            )
            .await?
        }
    };
    let codec = Codec::Ace(crate::codec::ace::Params {
        members: members.into(),
    });
    let stream = cx.decode_lazy(data, &codec, total)?;
    let solid = Arc::new(AceSolid {
        stream: Span::new(stream.source, 0, total),
        files,
        broken,
    });
    cx.cache(file, "ace solid", solid.clone());
    Ok(solid)
}

/// The ACE CRC-32 of `span` (read in pieces) and how much of it was read.
async fn ace_crc_of(cx: &Cx, span: Span) -> Result<(u32, u64)> {
    let mut crc = 0xffff_ffffu32;
    let mut pos = 0u64;
    while pos < span.len {
        let data = cx.read(span.sub(pos, 1 << 16)).await?;
        if data.is_empty() {
            break;
        }
        crc = crate::codec::crc::crc32_update(crc, &data);
        pos = pos.saturating_add(to_u64(data.len()));
    }
    Ok((crc, pos))
}

/// The packed data of a file, decoded on expansion (in a solid archive, as
/// a span of the archive's decoded stream).
async fn ace_content(
    cx: Cx,
    (input, data, member, solid): (Input, Span, crate::codec::ace::Member, bool),
) -> Result<()> {
    if !solid {
        let codec = Codec::Ace(crate::codec::ace::Params {
            members: vec![member].into(),
        });
        return crate::formats::expand_content(cx, (input, data, codec, Some(member.size))).await;
    }
    let run = ace_solid(&cx, input.span).await?;
    let i = run.files.partition_point(|&(o, _)| o < data.offset);
    let Some(&(_, offset)) = run.files.get(i).filter(|&&(o, _)| o == data.offset) else {
        return Err(if run.broken.is_some_and(|b| b < data.offset) {
            Diagnostic::unsupported("solid stream with an encrypted or split file before this one")
        } else {
            Diagnostic::malformed("file not found in the solid stream")
        });
    };
    let span = run.stream.sub(offset, member.size);
    if member.size <= SOLID_CHECK_LIMIT {
        let (crc, len) = ace_crc_of(&cx, span).await?;
        cx.annotate(format!("{len:#x} bytes decompressed"));
        if len < member.size {
            cx.diag(
                Diagnostic::malformed(format!("decoded {len:#x} of {:#x} bytes", member.size))
                    .at(data),
            );
        } else if crc != member.crc {
            cx.diag(Diagnostic::warning("ACE CRC-32 mismatch").at(data));
        }
    } else {
        cx.annotate(format!("{:#x} bytes, decoded on demand", member.size));
    }
    crate::formats::dissect_or_data(cx, input.nested(span)).await
}

async fn ace_block(
    cx: Cx,
    (input, span, header_span, solid): (Input, Span, Span, bool),
) -> Result<()> {
    let header = cx.read(header_span).await?;
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::truncated(header_span, 0);
    let stored = r.u16("Header CRC", LE).ok_or_else(bad)?;
    let computed = ace_crc(header.get(4..).unwrap_or_default());
    r.with(|n| {
        let n = n.value(hex(stored.into()));
        if stored == computed {
            n.summary("valid")
        } else {
            n.diag(Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#06x}"
            )))
        }
    });
    r.u16("Header size", LE).ok_or_else(bad)?;
    let kind = r.u8("Header type").ok_or_else(bad)?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: kind.into(),
            bits: 8,
            name: crate::value::lookup(ACE_TYPE, kind.into()),
        })
    });
    let flags = r.u16("Flags", LE).ok_or_else(bad)?;
    let table = match kind {
        0 => ACE_MAIN_FLAGS,
        1 | 3 => ACE_FILE_FLAGS,
        _ => ACE_RECOVERY_FLAGS,
    };
    r.with(|n| {
        let (set, unknown) = crate::value::decode_flags(table, flags.into());
        n.value(Value::Flags {
            raw: flags.into(),
            bits: 16,
            set,
            unknown,
        })
    });
    let mut extra: Vec<Node> = Vec::new();
    let data = span.tail(header_span.len);
    match kind {
        0 => {
            r.text("Signature", 7).ok_or_else(bad)?;
            for name in ["Version needed", "Version created"] {
                let v = r.u8(name).ok_or_else(bad)?;
                r.with(|n| n.summary(format!("{}.{}", v / 10, v % 10)));
            }
            let host = r.u8("Host OS").ok_or_else(bad)?;
            r.with(|n| {
                n.value(Value::Enum {
                    raw: host.into(),
                    bits: 8,
                    name: crate::value::lookup(ACE_HOST, host.into()),
                })
            });
            r.u8("Volume number").ok_or_else(bad)?;
            dos_time(&mut r, "Creation time").ok_or_else(bad)?;
            r.bytes("Reserved", 8).ok_or_else(bad)?;
            if flags & ACE_FLAG_ADVERT != 0 {
                let av = r.u8("Advert size").ok_or_else(bad)?;
                r.text("Advert", av.into()).ok_or_else(bad)?;
            }
            if flags & ACE_FLAG_COMMENT != 0 {
                extra.push(ace_comment(&mut r).ok_or_else(bad)?);
            }
        }
        1 | 3 => {
            let wide = kind == 3;
            let (packed, original) = if wide {
                let p = r.u64("Packed size", LE).ok_or_else(bad)?;
                (p, r.u64("Original size", LE).ok_or_else(bad)?)
            } else {
                let p = r.u32("Packed size", LE).ok_or_else(bad)?;
                (p.into(), r.u32("Original size", LE).ok_or_else(bad)?.into())
            };
            dos_time(&mut r, "Modification time").ok_or_else(bad)?;
            let attr = r.u32("Attributes", LE).ok_or_else(bad)?;
            r.with(|n| {
                let (set, unknown) = crate::value::decode_flags(ACE_ATTRIBUTES, attr.into());
                n.value(Value::Flags {
                    raw: attr.into(),
                    bits: 32,
                    set,
                    unknown,
                })
            });
            let crc = r.u32("CRC-32", LE).ok_or_else(bad)?;
            r.with(|n| n.value(hex(crc.into())).desc("ACE CRC-32 (not inverted)"));
            let comp = r.u8("Compression type").ok_or_else(bad)?;
            r.with(|n| {
                n.value(Value::Enum {
                    raw: comp.into(),
                    bits: 8,
                    name: crate::value::lookup(ACE_COMP, comp.into()),
                })
            });
            let quality = r.u8("Compression quality").ok_or_else(bad)?;
            r.with(|n| {
                n.value(Value::Enum {
                    raw: quality.into(),
                    bits: 8,
                    name: crate::value::lookup(ACE_QUALITY, quality.into()),
                })
            });
            let params = r.u16("Compression parameters", LE).ok_or_else(bad)?;
            r.with(|n| {
                n.value(hex(params.into())).summary(format!(
                    "dictionary {}",
                    human_size(1u64 << (u32::from(params & 15).saturating_add(10)))
                ))
            });
            r.u16("Reserved", LE).ok_or_else(bad)?;
            let len = r.u16("Name size", LE).ok_or_else(bad)?;
            r.text("Name", len.into()).ok_or_else(bad)?;
            if flags & ACE_FLAG_COMMENT != 0 {
                extra.push(ace_comment(&mut r).ok_or_else(bad)?);
            }
            if flags & ACE_FLAG_NTSECURITY != 0 {
                let n = r.u16("NT security size", LE).ok_or_else(bad)?;
                r.bytes("NT security descriptor", n.into())
                    .ok_or_else(bad)?;
            }
            let d = data.sub(0, packed);
            let member = crate::codec::ace::Member {
                packed,
                size: original,
                crc,
                method: comp,
            };
            let node = if flags & ACE_FLAG_PASSWORD != 0 {
                Node::new("Encrypted data")
                    .span(d)
                    .diag(Diagnostic::unsupported("ACE Blowfish encryption"))
            } else if flags & ACE_FLAG_SPLIT != 0 {
                Node::new("Data (split across volumes)")
                    .span(d)
                    .diag(Diagnostic::unsupported("multi-volume member"))
            } else if original == 0 && packed == 0 {
                Node::new("Content").span(d).summary("empty")
            } else if comp == 0 && !solid {
                embedded("Content", input.nested(d)).summary(human_size(packed))
            } else if comp <= 2 {
                Node::new("Content")
                    .span(d)
                    .summary(human_size(original))
                    .lazy(ace_content, (input, d, member, solid))
            } else {
                unsupported("Compressed data", d, &format!("ACE method {comp}"))
            };
            extra.push(crate::formats::util::arcutil::check_len(node, d, packed));
        }
        2 | 4 | 5 => {
            let wide = kind != 2;
            let size = if wide {
                r.u64("Recovery data size", LE).ok_or_else(bad)?
            } else {
                r.u32("Recovery data size", LE).ok_or_else(bad)?.into()
            };
            r.text("Signature", 7).ok_or_else(bad)?;
            let start = if wide {
                r.u64("Relative start", LE).ok_or_else(bad)?
            } else {
                r.u32("Relative start", LE).ok_or_else(bad)?.into()
            };
            r.with(|n| n.value(hex(start)));
            if kind == 5 {
                r.u16("Sectors", LE).ok_or_else(bad)?;
                r.u16("Sectors per cluster", LE).ok_or_else(bad)?;
                r.u32("Cluster size", LE).ok_or_else(bad)?;
            } else {
                r.u32("Clusters", LE).ok_or_else(bad)?;
                r.u32("Cluster size", LE).ok_or_else(bad)?;
                let c = r.u16("Recovery CRC", LE).ok_or_else(bad)?;
                r.with(|n| n.value(hex(c.into())));
            }
            extra.push(Node::new("Recovery data").span(data.sub(0, size)));
        }
        _ => {
            if flags & 0x0001 != 0 {
                extra.push(Node::new("Data").span(data));
            }
        }
    }
    if r.remaining() > 0 {
        r.bytes("Rest of header", to_u64(r.remaining()));
    }
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .lazy(emit_nodes, r.into_nodes()),
    );
    for node in extra {
        cx.emit(node);
    }
    Ok(())
}

/// A comment field (size and compressed text), decoded.
fn ace_comment(r: &mut ByteReader<'_>) -> Option<Node> {
    let len = r.u16("Comment size", LE)?;
    let start = r.at;
    let raw = r.bytes("Comment", len.into())?;
    let span = r.since(start);
    Some(match crate::codec::ace::comment(raw, 1 << 16) {
        Ok(text) => Node::new("Comment")
            .span(span)
            .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
        Err(e) => Node::new("Comment").span(span).diag(e),
    })
}

fn dos_time(r: &mut ByteReader<'_>, name: &'static str) -> Option<()> {
    let t = r.u32(name, LE)?;
    r.with(|n| {
        n.value(hex(t.into())).summary(crate::text::dos_datetime(
            u16::try_from(t >> 16).unwrap_or(0),
            u16::try_from(t & 0xffff).unwrap_or(0),
        ))
    });
    Some(())
}

// ---------------------------------------------------------------------------
// ARC

const ARC_METHOD: EnumTable = &[
    (0, "end of archive"),
    (1, "stored (old)"),
    (2, "stored"),
    (3, "packed (RLE)"),
    (4, "squeezed (RLE + Huffman)"),
    (5, "crunched (LZW, old)"),
    (6, "crunched (RLE + LZW, old)"),
    (7, "crunched (RLE + LZW, fast)"),
    (8, "crunched (RLE + dynamic LZW)"),
    (9, "squashed (13-bit LZW)"),
    (10, "crushed (PAK)"),
    (11, "distilled (PAK)"),
];

fn probe_arc(h: &Head<'_>) -> bool {
    let d = h.data;
    let method_ok = d.get(1).is_some_and(|&m| (1..=11).contains(&m));
    let name = d.get(2..15).unwrap_or_default();
    let nul = name.iter().position(|&b| b == 0);
    let name_ok = nul.is_some_and(|n| {
        n > 0
            && name
                .get(..n)
                .is_some_and(|s| s.iter().all(|&c| c.is_ascii_graphic()))
    });
    let size_ok = u32_le(d, 15).is_some_and(|s| u64::from(s) <= h.len);
    d.first() == Some(&0x1a) && method_ok && name_ok && size_ok
}

pub async fn dissect_arc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let mut files = 0u64;
    let mut total = 0u64;
    let mut seen = 0u64;
    while at < file.len && seen < MAX_ENTRIES {
        seen = seen.saturating_add(1);
        let head = cx.read_avail(file.sub(at, 29)).await?;
        if head.first() != Some(&0x1a) {
            cx.emit(
                Node::new("Trailing data")
                    .span(file.tail(at))
                    .diag(Diagnostic::malformed("expected a 0x1A header marker")),
            );
            break;
        }
        let method = head.get(1).copied().unwrap_or(0);
        if method == 0 {
            cx.emit(Node::new("End of archive").span(file.sub(at, 2)));
            at = at.saturating_add(2);
            break;
        }
        let header_len = if method == 1 { 25u64 } else { 29 };
        let packed = u64::from(u32_le(&head, 15).unwrap_or(0));
        let original = if method == 1 {
            packed
        } else {
            u64::from(u32_le(&head, 25).unwrap_or(0))
        };
        let name = crate::text::until_nul(head.get(2..15).unwrap_or_default());
        let span = file.sub(at, header_len.saturating_add(packed));
        files = files.saturating_add(1);
        total = total.saturating_add(original);
        let m = crate::value::lookup(ARC_METHOD, method.into()).unwrap_or("unknown method");
        cx.progress_in(file, span.end());
        cx.push(
            Node::new(name)
                .span(span)
                .summary(format!("{}, {m}", human_size(original)))
                .lazy(arc_entry, (input, span, header_len)),
        )
        .await;
        at = at.saturating_add(span.len.max(2));
    }
    if at < file.len {
        cx.emit(Node::new("Data after the archive").span(file.tail(at)));
    }
    cx.annotate(format!(
        "ARC archive, {}, {} uncompressed",
        count(files, "file", "files"),
        human_size(total)
    ));
    Ok(())
}

async fn arc_entry(cx: Cx, (input, span, header_len): (Input, Span, u64)) -> Result<()> {
    let header_span = span.sub(0, header_len);
    let header = cx.read(header_span).await?;
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::truncated(header_span, 0);
    r.u8("Marker").ok_or_else(bad)?;
    let method = r.u8("Method").ok_or_else(bad)?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: method.into(),
            bits: 8,
            name: crate::value::lookup(ARC_METHOD, method.into()),
        })
    });
    let raw = r.bytes("Name", 13).ok_or_else(bad)?;
    let name = crate::text::until_nul(raw);
    r.with(|n| n.value(Value::Text(name)));
    let packed = r.u32("Compressed size", LE).ok_or_else(bad)?;
    let date = r.u16("Date", LE).ok_or_else(bad)?;
    let time = r.u16("Time", LE).ok_or_else(bad)?;
    r.with(|n| n.summary(crate::text::dos_datetime(date, time)));
    let crc = r.u16("CRC-16", LE).ok_or_else(bad)?;
    r.with(|n| n.value(hex(crc.into())));
    if method != 1 {
        r.u32("Original size", LE).ok_or_else(bad)?;
    }
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .lazy(emit_nodes, r.into_nodes()),
    );
    let data = span.sub(header_len, packed.into());
    let node = if method <= 2 {
        embedded("Content", input.nested(data)).summary(human_size(packed.into()))
    } else {
        let m = crate::value::lookup(ARC_METHOD, method.into()).unwrap_or("unknown");
        unsupported("Compressed data", data, &format!("ARC {m}"))
    };
    cx.emit(crate::formats::util::arcutil::check_len(
        node,
        data,
        packed.into(),
    ));
    Ok(())
}
