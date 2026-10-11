//! gzip (RFC 1952).
//!
//! The top level shows the header and the trailer. Small files are walked
//! member by member (each member's DEFLATE data decoded to find where it
//! ends), so several members (`cat a.gz b.gz`) and padding after the stream
//! are shown as they are and the size is the real total. For larger files
//! the trailer is read from the end of the file, which gives the original
//! size without decompressing, and the members are walked only when their
//! node is expanded. The content is decompressed only when expanded, then
//! dissected in place (e.g. a tarball).

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::codec::pipeline::Status;
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Codec, Format, Input, Probe, content_hinted};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "gzip",
    title: "gzip compressed data",
    extensions: &["gz", "tgz", "svgz", "emz", "wmz"],
    mime: "application/gzip",
    probe: Probe::Magic(&[(0, b"\x1f\x8b\x08")]),
    dissect: crate::expander!(dissect: Input),
};

const METHOD: EnumTable = &[(8, "deflate")];

const FLAGS: FlagTable = &[
    flag(0x01, "FTEXT"),
    flag(0x02, "FHCRC"),
    flag(0x04, "FEXTRA"),
    flag(0x08, "FNAME"),
    flag(0x10, "FCOMMENT"),
];

const OS: EnumTable = &[
    (0, "FAT"),
    (1, "Amiga"),
    (2, "VMS"),
    (3, "Unix"),
    (4, "VM/CMS"),
    (5, "Atari TOS"),
    (6, "HPFS"),
    (7, "Macintosh"),
    (8, "Z-System"),
    (9, "CP/M"),
    (10, "TOPS-20"),
    (11, "NTFS"),
    (12, "QDOS"),
    (13, "Acorn RISCOS"),
    (255, "unknown"),
];

const XFL: EnumTable = &[(0, "default"), (2, "best compression"), (4, "fastest")];

record! {
    pub struct Header {
        magic: bytes[2] "ID",
        method: u8 "CM" .enumeration(METHOD),
        flags: u8 "FLG" .flags(FLAGS),
        mtime: u32 "MTIME" .timestamp().desc("Modification time of the original file (0 if unknown)"),
        extra_flags: u8 "XFL" .enumeration(XFL),
        os: u8 "OS" .enumeration(OS),
    }
}

record! {
    pub struct Trailer {
        crc: u32 "CRC32" .hex().desc("CRC-32 of the uncompressed data"),
        size: u32 "ISIZE" .desc("Uncompressed size modulo 2^32"),
    }
}

/// Registered extra subfield ids (SI1 SI2).
const SUBFIELDS: &[(&[u8; 2], &str)] = &[
    (b"AC", "Acorn RISC OS file type"),
    (b"Ap", "Apollo file type"),
    (b"BC", "BGZF block size"),
    (b"cp", "compressed by cpio"),
    (b"GS", "gzsig signature"),
    (b"KN", "KeyNote assertion"),
    (b"Mc", "Macintosh type and creator"),
    (b"RA", "random access index (dictzip)"),
    (b"RO", "Acorn RISC OS file type"),
];

/// The FEXTRA field (XLEN, then subfields of SI1 SI2 LEN data), spanning
/// `span`; `data` is the field's XLEN bytes at `data_span`. Also used by
/// BGZF, whose blocks are gzip members with a `BC` subfield.
pub fn extra_field(span: Span, data: &[u8], data_span: Span) -> Node {
    let mut children = vec![
        Node::new("XLEN")
            .span(span.sub(0, 2))
            .value(uint(data_span.len, 16)),
    ];
    let mut at = 0usize;
    let mut count = 0u64;
    while let (Some(id), Some(len)) = (
        data.get(at..at.saturating_add(2)),
        u16_le(data, at.saturating_add(2)),
    ) {
        let len = usize::from(len);
        let body_at = at.saturating_add(4);
        let sub = data_span.sub(to_u64(at), to_u64(len.saturating_add(4)));
        let body = data_span.sub(to_u64(body_at), to_u64(len));
        let known = SUBFIELDS
            .iter()
            .find(|(k, _)| k.as_slice() == id)
            .map(|(_, v)| *v);
        let id_text = String::from_utf8_lossy(id).into_owned();
        let mut data_node = Node::new("Data").span(body);
        if id == b"BC" && len == 2 {
            let bsize = u16_le(data, body_at).unwrap_or(0);
            data_node = data_node
                .value(uint(bsize, 16))
                .summary(format!("block size {}", u32::from(bsize).saturating_add(1)));
        }
        let mut node = Node::new(format!("Subfield {id_text}"))
            .span(sub)
            .summary(match known {
                Some(what) => format!("{what}, {}", size(to_u64(len))),
                None => size(to_u64(len)),
            });
        if body.len < to_u64(len) {
            node = node.diag(Diagnostic::truncated(body, body.len));
        }
        children.push(node.lazy(
            emit_nodes,
            Arc::new(vec![
                Node::new("SI1 SI2").span(sub.sub(0, 2)).value(text(id_text)),
                Node::new("LEN").span(sub.sub(2, 2)).value(uint(to_u64(len), 16)),
                data_node,
            ]),
        ));
        count = count.saturating_add(1);
        at = body_at.saturating_add(len);
    }
    if at < data.len() {
        children.push(
            Node::new("Trailing bytes")
                .span(data_span.tail(to_u64(at)))
                .diag(Diagnostic::malformed("not a whole subfield")),
        );
    }
    Node::new("Extra field")
        .span(span)
        .summary(format!(
            "{}, {}",
            crate::formats::util::fmt::count(count, "subfield", "subfields"),
            size(data_span.len)
        ))
        .lazy(emit_nodes, Arc::new(children))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let name = header_nodes(&cx, &mut cur).await?;
    let body_start = cur.pos();

    // Small files are walked member by member now, so the trailer and the
    // total are the real ones even with several members or padding after
    // the stream. For larger files only the last 8 bytes are read: they are
    // the trailer of a single-member file with nothing after it, which is
    // by far the common case, but nothing indexes the members.
    let walked = if file.len <= EAGER_LEN {
        walk(&cx, file, EAGER_OUTPUT, EAGER_MEMBERS)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let mut summary = String::from("gzip");
    if let Some(name) = &name {
        summary = format!("{summary}, originally {name}");
    }
    let hint;
    match &walked {
        Some(walk) => {
            let total = walk
                .members
                .iter()
                .fold(0u64, |t, m| t.saturating_add(m.decoded));
            hint = total;
            if let [only] = walk.members.as_slice() {
                let span = file.sub(only.trailer(), 8);
                let recorded = cx.read_avail(span).await?;
                cx.emit(checked_trailer(span, only, &recorded));
            } else {
                summary = format!(
                    "{summary}, {}",
                    crate::formats::util::fmt::count(
                        to_u64(walk.members.len()),
                        "member",
                        "members"
                    )
                );
            }
            summary = format!("{summary}, {total} bytes uncompressed");
            if walk.members.len() > 1 || walk.end < file.len {
                cx.emit(members_node(input, Some(walk)));
            }
        }
        None => {
            let trailer_span = file.tail(file.len.saturating_sub(8));
            let trailer = cx.read_avail(trailer_span).await?;
            let size = u32_le(&trailer, 4);
            // Eight zero bytes are padding (dd, tape blocks) far more often
            // than the trailer of an empty member.
            let padded = trailer.iter().all(|&b| b == 0);
            if trailer.len() < 8 {
                cx.diag(Diagnostic::truncated(trailer_span, to_u64(trailer.len())));
            } else if !padded {
                cx.emit(Trailer::node("Trailer", trailer_span, LE).desc(
                    "The last 8 bytes; the trailer if the file is one member with nothing after it",
                ));
            }
            hint = size.filter(|_| !padded).map_or(0, u64::from);
            if let Some(size) = size.filter(|_| !padded) {
                summary = format!("{summary}, {size} bytes uncompressed (last trailer)");
            }
            cx.emit(members_node(input, None));
        }
    }
    cx.annotate(summary);
    // The content is every member, decoded one after another. Nothing
    // records the total: ISIZE is one member's size modulo 2^32, so it only
    // hints whether to decode on demand; the size is found by decoding.
    let body_len = file.len.saturating_sub(body_start);
    cx.emit(
        content_hinted("Content", input, file.tail(body_start), Codec::Gzip, hint)
            .summary(format!("{body_len:#x} compressed bytes")),
    );
    Ok(())
}

/// Emits the member header at the cursor (fixed fields and the optional
/// ones); returns the original file name, if recorded.
async fn header_nodes(cx: &Cx, cur: &mut Cursor<'_>) -> Result<Option<String>> {
    let (header, header_span) = cur.record::<Header>().await?;
    cx.emit(Header::node("Header", header_span, LE));
    if header.flags & 0x04 != 0 {
        let start = cur.pos();
        let xlen = cur.u16().await?;
        let data_span = cur.span(xlen.into());
        let data = cur.bytes(xlen.into()).await?;
        cx.emit(extra_field(cur.since(start), &data, data_span));
    }
    let mut name = None;
    if header.flags & 0x08 != 0 {
        let (text, span) = cur.cstr(4096).await?;
        cx.emit(
            Node::new("Original name")
                .span(span)
                .value(Value::Text(text.clone())),
        );
        name = Some(text);
    }
    if header.flags & 0x10 != 0 {
        let (text, span) = cur.cstr(65536).await?;
        cx.emit(Node::new("Comment").span(span).value(Value::Text(text)));
    }
    if header.flags & 0x02 != 0 {
        let start = cur.pos();
        let crc = cur.u16().await?;
        cx.emit(
            Node::new("Header CRC16")
                .span(cur.since(start))
                .value(hex(crc, 16)),
        );
    }
    Ok(name)
}

/// Files up to this size have their members walked (decoded) when the file
/// is expanded, so the trailer and total shown are exact. Larger files show
/// the last 8 bytes as the trailer and walk members only on request.
const EAGER_LEN: u64 = 64 * 1024;
/// Output the eager walk may decode before giving up (a small file can
/// decode to a lot).
const EAGER_OUTPUT: u64 = 16 << 20;
/// Members the eager walk lists at most.
const EAGER_MEMBERS: usize = 64;
/// Compressed bytes read per step while walking a member.
const CHUNK: u64 = 64 * 1024;
/// Decoded bytes per step between checkpoints.
const STEP: usize = 64 * 1024;
/// The longest member header (as in the codec): fixed fields, an extra
/// field, a name and a comment of up to 64 KiB each, a header CRC.
const MAX_HEADER: u64 = 10 + 2 + 65_535 + 2 * 65_536 + 2;

/// One member, found by decoding it. Offsets are relative to the file.
#[derive(Clone, Copy, Debug)]
struct Member {
    start: u64,
    header_len: u64,
    /// Length of the DEFLATE data.
    body_len: u64,
    /// CRC-32 of what it decoded to, and its length.
    crc: u32,
    decoded: u64,
}

impl Member {
    fn body(&self) -> u64 {
        self.start.saturating_add(self.header_len)
    }
    fn trailer(&self) -> u64 {
        self.body().saturating_add(self.body_len)
    }
    fn end(&self) -> u64 {
        self.trailer().saturating_add(8)
    }
    /// The decoded size modulo 2^32, as ISIZE records it.
    fn isize(&self) -> u32 {
        u32::try_from(self.decoded & 0xffff_ffff).unwrap_or(0)
    }
}

/// Whether a member starts at `at` (as the codec decides: `1f 8b`, then the
/// method byte, which must be DEFLATE).
async fn member_starts(cx: &Cx, file: Span, at: u64) -> Result<bool> {
    let magic = cx.read_avail(file.sub(at, 3)).await?;
    Ok(magic == b"\x1f\x8b\x08")
}

/// Decodes the member whose header starts at `start` to find its end,
/// keeping only the DEFLATE window in memory. `None` if it decodes to more
/// than `budget` bytes.
async fn member_at(cx: &Cx, file: Span, start: u64, budget: u64) -> Result<Option<Member>> {
    let head = cx.read_avail(file.sub(start, 4096)).await?;
    let header_len = match crate::codec::gzip::header_len(&head) {
        Ok(n) => n,
        Err(_) if head.len() == 4096 => {
            let head = cx.read_avail(file.sub(start, MAX_HEADER)).await?;
            crate::codec::gzip::header_len(&head).map_err(|e| e.at(file.sub(start, MAX_HEADER)))?
        }
        Err(e) => return Err(e.at(file.sub(start, to_u64(head.len())))),
    };
    let body = start.saturating_add(to_u64(header_len));
    let mut decoder = Codec::Deflate
        .decoder()
        .ok_or_else(|| Diagnostic::unsupported("DEFLATE"))?;
    let mut input = Vec::new();
    let mut in_base = body;
    let mut eof = false;
    let mut out = Vec::new();
    // Bytes at the front of `out` already counted (the window kept).
    let mut seen = 0usize;
    let mut crc = !0u32;
    let mut decoded = 0u64;
    loop {
        let status = decoder
            .decode(&input, eof, &mut out, STEP, usize::MAX)
            .map_err(|e| e.at(file.tail(body)))?;
        let fresh = out.get(seen..).unwrap_or_default();
        crc = crate::codec::crc::crc32_update(crc, fresh);
        decoded = decoded.saturating_add(to_u64(fresh.len()));
        let n = decoder.releasable_output(out.len()).min(out.len());
        out.drain(..n);
        decoder.release_output(n);
        seen = out.len();
        let n = decoder.releasable_input().min(input.len());
        input.drain(..n);
        decoder.release_input(n);
        in_base = in_base.saturating_add(to_u64(n));
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
                    return Err(Diagnostic::malformed("truncated gzip member").at(file.tail(start)));
                }
                let at = in_base.saturating_add(to_u64(input.len()));
                let data = cx.read_avail(file.sub(at, CHUNK)).await?;
                eof = data.is_empty();
                input.extend_from_slice(&data);
            }
        }
    }
    let body_len = in_base
        .saturating_add(to_u64(decoder.consumed()))
        .saturating_sub(body);
    Ok(Some(Member {
        start,
        header_len: to_u64(header_len),
        body_len,
        crc: !crc,
        decoded,
    }))
}

/// The members found from the start, and where the last one ends.
struct Walk {
    members: Vec<Member>,
    end: u64,
}

/// Walks members from the start of the file, giving up (`None`) after
/// `max_members` or once they decode to more than `budget` bytes.
async fn walk(cx: &Cx, file: Span, budget: u64, max_members: usize) -> Result<Option<Walk>> {
    let mut members = Vec::new();
    let mut at = 0u64;
    let mut left = budget;
    while at < file.len && member_starts(cx, file, at).await? {
        if members.len() >= max_members {
            return Ok(None);
        }
        let Some(m) = member_at(cx, file, at, left).await? else {
            return Ok(None);
        };
        left = left.saturating_sub(m.decoded);
        at = m.end();
        members.push(m);
    }
    Ok(Some(Walk { members, end: at }))
}

/// The trailer of `m` (`recorded` is its bytes at `span`), checked against
/// what the member decoded to.
fn checked_trailer(span: Span, m: &Member, recorded: &[u8]) -> Node {
    let mut node = Trailer::node("Trailer", span, LE);
    if recorded.len() < 8 {
        return node.diag(Diagnostic::truncated(span, to_u64(recorded.len())));
    }
    if u32_le(recorded, 0) != Some(m.crc) {
        node = node.diag(Diagnostic::warning(format!(
            "CRC-32 mismatch: the data decodes to {:#010x}",
            m.crc
        )));
    } else if u32_le(recorded, 4) != Some(m.isize()) {
        node = node.diag(Diagnostic::warning(format!(
            "ISIZE mismatch: the data decodes to {} bytes",
            m.decoded
        )));
    }
    node
}

/// The member list: from a walk already made, or walked on expansion.
fn members_node(input: Input, walk: Option<&Walk>) -> Node {
    let node = Node::new("Members").span(input.span);
    match walk {
        Some(w) => node.summary(crate::formats::util::fmt::count(
            to_u64(w.members.len()),
            "member",
            "members",
        )),
        None => node.summary("found by decoding"),
    }
    .lazy(members, input)
}

async fn members(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // Resume marks: (position, members so far).
    let (mut at, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while at < file.len && member_starts(&cx, file, at).await? {
        let mark = (at, index);
        cx.mark(move || mark);
        index = index.saturating_add(1);
        let m = match member_at(&cx, file, at, u64::MAX).await {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(e) => {
                cx.push(
                    Node::new(format!("Member {index}"))
                        .span(file.tail(at))
                        .diag(e),
                )
                .await;
                return Ok(());
            }
        };
        let span = file.sub(m.start, m.end().saturating_sub(m.start));
        cx.push(
            Node::new(format!("Member {index}"))
                .span(span)
                .summary(format!(
                    "{:#x} compressed bytes, {} bytes uncompressed",
                    m.body_len, m.decoded
                ))
                .lazy(member, (file, m)),
        )
        .await;
        at = m.end();
    }
    if at < file.len {
        let rest = file.tail(at);
        let probe = cx.read_avail(rest.sub(0, 4096)).await?;
        let zeros = probe.iter().all(|&b| b == 0);
        let mut node = Node::new("Trailing data").span(rest);
        node = if zeros && to_u64(probe.len()) == rest.len {
            node.summary(format!("{}, zero padding", size(rest.len)))
        } else {
            node.summary(size(rest.len))
                .diag(Diagnostic::note("not another gzip member"))
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn member(cx: Cx, (file, m): (Span, Member)) -> Result<()> {
    let mut cur = Cursor::new(&cx, file.sub(m.start, m.header_len), LE);
    header_nodes(&cx, &mut cur).await?;
    cx.emit(
        Node::new("Compressed data")
            .span(file.sub(m.body(), m.body_len))
            .summary(format!("DEFLATE, {} bytes uncompressed", m.decoded)),
    );
    let span = file.sub(m.trailer(), 8);
    let recorded = cx.read_avail(span).await?;
    cx.emit(checked_trailer(span, &m, &recorded));
    Ok(())
}
