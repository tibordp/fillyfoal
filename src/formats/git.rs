//! Git storage files: packfiles (`.pack`), pack indexes (`.idx`, version 2)
//! and the index (`.git/index`, `DIRC`, versions 2 to 4).
//!
//! Pack objects record their uncompressed size but not their compressed
//! length, so listing objects means inflating each one (a page at a time);
//! the decoded data is cached and reused when an object is expanded.
//! Commits and tags are shown as headers and message, trees as entries,
//! deltas as copy/insert instructions, and blobs are dissected as content.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::codec::inflate_span;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::datakit::{clip, hex_string, sha1, size};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

const BE: Endian = Endian::Big;
const HASH: u64 = 20;

pub static PACK: Format = Format {
    name: "git-pack",
    title: "Git packfile",
    extensions: &["pack"],
    mime: "application/x-git-pack",
    probe: Probe::Magic(&[(0, b"PACK\x00\x00\x00\x02"), (0, b"PACK\x00\x00\x00\x03")]),
    dissect: crate::expander!(pack: Input),
};

pub static PACK_INDEX: Format = Format {
    name: "git-pack-index",
    title: "Git pack index",
    extensions: &["idx"],
    mime: "application/x-git-pack-index",
    probe: Probe::Magic(&[(0, b"\xfftOc\x00\x00\x00\x02")]),
    dissect: crate::expander!(pack_index: Input),
};

pub static INDEX: Format = Format {
    name: "git-index",
    title: "Git index (staging area)",
    extensions: &[],
    mime: "application/x-git-index",
    probe: Probe::Magic(&[
        (0, b"DIRC\x00\x00\x00\x02"),
        (0, b"DIRC\x00\x00\x00\x03"),
        (0, b"DIRC\x00\x00\x00\x04"),
    ]),
    dissect: crate::expander!(index: Input),
};

const OBJECT_TYPES: EnumTable = &[
    (1, "commit"),
    (2, "tree"),
    (3, "blob"),
    (4, "tag"),
    (6, "ofs-delta"),
    (7, "ref-delta"),
];

/// A trailing SHA-1 over everything before it.
async fn checksum_node(cx: &Cx, file: Span, name: &'static str) -> Result<Node> {
    let at = file.len.saturating_sub(HASH);
    let span = file.sub(at, HASH);
    let stored = cx.read(span).await?;
    let mut node = Node::new(name).span(span).value(Value::Text(hex_string(&stored)));
    if at <= cx.limits().max_read {
        let body = cx.read(file.sub(0, at)).await?;
        node = if sha1(&body).as_slice() == stored.as_slice() {
            node.summary("valid")
        } else {
            node.diag(Diagnostic::warning("SHA-1 mismatch"))
        };
    }
    Ok(node)
}

/// The variable-length object header: type, size and header length.
fn object_header(data: &[u8]) -> Option<(u8, u64, u64)> {
    let first = *data.first()?;
    let kind = (first >> 4) & 7;
    let mut size = u64::from(first & 0x0f);
    let mut shift = 4u32;
    let mut i = 0usize;
    let mut byte = first;
    while byte & 0x80 != 0 {
        i = i.saturating_add(1);
        byte = *data.get(i)?;
        size |= u64::from(byte & 0x7f).checked_shl(shift)?;
        shift = shift.checked_add(7).filter(|&s| s < 64)?;
    }
    Some((kind, size, to_u64(i).saturating_add(1)))
}

/// The base offset of an ofs-delta (a big-endian base-128 number where each
/// continuation also adds one).
fn delta_offset(data: &[u8]) -> Option<(u64, u64)> {
    let mut i = 0usize;
    let mut byte = *data.first()?;
    let mut value = u64::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        i = i.saturating_add(1);
        if i > 9 {
            return None;
        }
        byte = *data.get(i)?;
        value = value.checked_add(1)?.checked_shl(7)? | u64::from(byte & 0x7f);
    }
    Some((value, to_u64(i).saturating_add(1)))
}

#[derive(Clone, Copy, Debug)]
struct Object {
    input: Input,
    /// The object, from its header to the end of the compressed data.
    span: Span,
    kind: u8,
    size: u64,
    /// Header (and delta base) length.
    header: u64,
    /// The span handed to the inflater (shared with the listing, so the
    /// decoded data is cached).
    stream: Span,
}

/// An upper bound for the compressed size of `size` bytes.
fn bound(size: u64) -> u64 {
    size.saturating_add(size / 8).saturating_add(64)
}

pub async fn pack(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, 12)?).await?;
    let count = u32_be(&head, 8).unwrap_or(0);
    cx.emit(struct_node("Header", file.sub(0, 12), BE, (), |f, _| {
        f.ascii("Signature", 4).emit()?;
        f.u32("Version").emit()?;
        f.u32("Number of objects").emit()?;
        Ok(())
    }));
    cx.annotate(format!(
        "Git pack v{}, {count} objects",
        u32_be(&head, 4).unwrap_or(0)
    ));
    let body_end = file.len.saturating_sub(HASH);
    cx.emit(checksum_node(&cx, file, "Pack checksum").await?);
    cx.set_count(Count::Exact(u64::from(count).saturating_add(2)));
    let mut pos = 12u64;
    for index in 0..count {
        if pos >= body_end {
            cx.diag(Diagnostic::truncated(file.sub(pos, 0), 0));
            break;
        }
        let head = cx.read_avail(file.sub(pos, 32)).await?;
        let (kind, size, mut header) = object_header(&head)
            .ok_or_else(|| Diagnostic::malformed("bad object header").at(file.sub(pos, 1)))?;
        let mut base = String::new();
        match kind {
            6 => {
                let rest = head.get(to_usize(header)..).unwrap_or_default();
                let (offset, len) = delta_offset(rest)
                    .ok_or_else(|| Diagnostic::malformed("bad delta offset").at(file.sub(pos, 1)))?;
                base = format!(", base at {:#x}", pos.saturating_sub(offset));
                header = header.saturating_add(len);
            }
            7 => {
                let sha = cx.read(file.sub_exact(pos.saturating_add(header), HASH)?).await?;
                base = format!(", base {}", hex_string(&sha));
                header = header.saturating_add(HASH);
            }
            1..=4 => {}
            _ => {
                return Err(Diagnostic::malformed(format!("object type {kind}")).at(file.sub(pos, 1)));
            }
        }
        let start = pos.saturating_add(header);
        let stream = file.sub(start, bound(size).min(body_end.saturating_sub(start)));
        let decoded = inflate_span(&cx, stream, true, Some(size)).await?;
        let span = file.sub(pos, header.saturating_add(decoded.consumed));
        let name = lookup(OBJECT_TYPES, kind.into()).unwrap_or("?");
        let mut node = Node::new(format!("{name} at {pos:#x}"))
            .span(span)
            .summary(format!("object {index}, {} → {size} bytes{base}", decoded.consumed))
            .lazy(
                object,
                Object {
                    input,
                    span,
                    kind,
                    size,
                    header,
                    stream,
                },
            );
        if let Some(e) = decoded.error {
            node = node.diag(e);
        }
        cx.push(node).await;
        pos = span.end().saturating_sub(file.offset);
    }
    if pos < body_end {
        cx.emit(Node::new("Unused data").span(file.sub(pos, body_end.saturating_sub(pos))));
    }
    Ok(())
}

async fn object(cx: Cx, o: Object) -> Result<()> {
    let head = cx.block(o.span.sub(0, o.header)).await?;
    {
        let mut f = Fields::emitting(&cx, &head, BE);
        let first = f.u8("Type and size").hex().emit()?;
        f.node(
            Node::new("Type").value(Value::Enum {
                raw: ((first >> 4) & 7).into(),
                bits: 3,
                name: lookup(OBJECT_TYPES, ((first >> 4) & 7).into()),
            }),
        );
        f.node(Node::new("Size").value(Value::UInt {
            value: o.size,
            bits: 64,
            radix: crate::value::Radix::Dec,
        }));
    }
    let decoded = inflate_span(&cx, o.stream, true, Some(o.size)).await?;
    cx.emit(
        Node::new("Compressed data")
            .span(o.stream.sub(0, decoded.consumed))
            .summary(format!("zlib, {} bytes", decoded.consumed)),
    );
    let data = decoded.span;
    match o.kind {
        1 | 4 => commit_like(&cx, data).await?,
        2 => cx.emit(Node::new("Entries").span(data).lazy(tree_entries, data)),
        3 => cx.emit(
            Node::new("Content")
                .span(data)
                .summary(size(data.len))
                .lazy(blob, (o.input, data)),
        ),
        _ => cx.emit(Node::new("Delta").span(data).lazy(delta, data)),
    }
    Ok(())
}

async fn blob(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    crate::formats::dissect_or_data(cx, input.nested(data)).await
}

/// Commit and tag objects: header lines, a blank line, the message.
async fn commit_like(cx: &Cx, data: Span) -> Result<()> {
    let bytes = cx.read(data.sub(0, 0x10000)).await?;
    let mut at = 0usize;
    let mut message_at = None;
    for line in bytes.split(|&b| b == b'\n') {
        let len = line.len();
        let span = data.sub(to_u64(at), to_u64(len));
        if line.is_empty() {
            message_at = Some(at.saturating_add(1));
            break;
        }
        let text = String::from_utf8_lossy(line).into_owned();
        let (key, value) = text.split_once(' ').unwrap_or((text.as_str(), ""));
        let mut node = Node::new(key.to_owned()).span(span);
        // author/committer/tagger: "Name <email> 1234567890 +0000"
        if matches!(key, "author" | "committer" | "tagger")
            && let Some((who, when)) = value.rsplit_once("> ")
        {
            let seconds = when.split_whitespace().next().and_then(|s| s.parse::<i64>().ok());
            node = node.value(Value::Text(format!("{who}>")));
            if let Some(s) = seconds {
                node = node.summary(format!(
                    "{} {}",
                    crate::render::value(&Value::Timestamp { unix_seconds: s }),
                    when.split_whitespace().nth(1).unwrap_or_default()
                ));
            }
        } else {
            node = node.value(Value::Text(value.to_owned()));
        }
        cx.emit(node);
        at = at.saturating_add(len).saturating_add(1);
    }
    if let Some(m) = message_at {
        let span = data.tail(to_u64(m));
        let text = String::from_utf8_lossy(bytes.get(m..).unwrap_or_default()).into_owned();
        cx.emit(Node::new("Message").span(span).value(Value::Text(clip(text.trim_end(), 4000))));
    }
    Ok(())
}

async fn tree_entries(cx: Cx, data: Span) -> Result<()> {
    let bytes = cx.read(data).await?;
    let mut at = 0usize;
    while at < bytes.len() {
        let rest = bytes.get(at..).unwrap_or_default();
        let Some(nul) = rest.iter().position(|&b| b == 0) else {
            return Err(Diagnostic::malformed("unterminated tree entry").at(data.tail(to_u64(at))));
        };
        let head = String::from_utf8_lossy(rest.get(..nul).unwrap_or_default()).into_owned();
        let (mode, name) = head.split_once(' ').unwrap_or(("?", head.as_str()));
        let sha = rest.get(nul.saturating_add(1)..nul.saturating_add(21)).unwrap_or_default();
        let len = nul.saturating_add(21);
        let kind = match mode {
            "40000" => "tree",
            "160000" => "submodule",
            "120000" => "symlink",
            _ => "blob",
        };
        cx.push(
            Node::new(name.to_owned())
                .span(data.sub(to_u64(at), to_u64(len)))
                .value(Value::Text(hex_string(sha)))
                .summary(format!("{mode} {kind}")),
        )
        .await;
        at = at.saturating_add(len);
    }
    Ok(())
}

/// Delta data: source and target sizes, then copy/insert instructions.
async fn delta(cx: Cx, data: Span) -> Result<()> {
    let bytes = cx.read(data).await?;
    let mut at = 0usize;
    for name in ["Source size", "Target size"] {
        let (v, n) = crate::bytes::uleb128(bytes.get(at..).unwrap_or_default())
            .ok_or_else(|| Diagnostic::malformed("bad delta size").at(data))?;
        cx.emit(Node::new(name).span(data.sub(to_u64(at), to_u64(n))).value(Value::UInt {
            value: v,
            bits: 64,
            radix: crate::value::Radix::Dec,
        }));
        at = at.saturating_add(n);
    }
    while let Some(&op) = bytes.get(at) {
        let start = at;
        at = at.saturating_add(1);
        let node = if op & 0x80 != 0 {
            let mut offset = 0u64;
            let mut len = 0u64;
            for bit in 0..7u32 {
                if op & (1 << bit) != 0 {
                    let b = u64::from(bytes.get(at).copied().unwrap_or(0));
                    at = at.saturating_add(1);
                    if bit < 4 {
                        offset |= b.checked_shl(bit.saturating_mul(8)).unwrap_or(0);
                    } else {
                        len |= b.checked_shl(bit.saturating_sub(4).saturating_mul(8)).unwrap_or(0);
                    }
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            Node::new("Copy").summary(format!("{len} bytes from source offset {offset:#x}"))
        } else if op == 0 {
            Node::new("Reserved").diag(Diagnostic::malformed("delta opcode 0"))
        } else {
            let n = usize::from(op);
            at = at.saturating_add(n);
            Node::new("Insert").summary(format!("{n} literal bytes"))
        };
        cx.push(node.span(data.sub(to_u64(start), to_u64(at.saturating_sub(start)))))
            .await;
    }
    Ok(())
}

pub async fn pack_index(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let fanout = file.sub_exact(8, 1024)?;
    let table = cx.read(fanout).await?;
    let count = u64::from(u32_be(&table, 1020).unwrap_or(0));
    cx.emit(struct_node("Header", file.sub(0, 8), BE, (), |f, _| {
        f.bytes("Magic", 4).emit()?;
        f.u32("Version").emit()?;
        Ok(())
    }));
    cx.annotate(format!("Git pack index v2, {count} objects"));
    cx.emit(
        Node::new("Fan-out table")
            .span(fanout)
            .summary("cumulative object counts by first byte")
            .lazy(fanout_table, fanout),
    );
    let names = file.sub_exact(1032, count.saturating_mul(HASH))?;
    let crcs = file.sub_exact(names.end().saturating_sub(file.offset), count.saturating_mul(4))?;
    let offsets = file.sub_exact(crcs.end().saturating_sub(file.offset), count.saturating_mul(4))?;
    cx.emit(
        Node::new("Objects")
            .span(names)
            .summary(format!("{count}"))
            .lazy(index_objects, (file, names, crcs, offsets, count)),
    );
    cx.emit(Node::new("CRC-32 table").span(crcs));
    cx.emit(Node::new("Offset table").span(offsets));
    let trailer_at = file.len.saturating_sub(2 * HASH);
    let large_at = offsets.end().saturating_sub(file.offset);
    if trailer_at > large_at {
        cx.emit(Node::new("Large offsets").span(file.sub(large_at, trailer_at.saturating_sub(large_at))));
    }
    let pack_sum = file.sub(trailer_at, HASH);
    cx.emit(
        Node::new("Pack checksum")
            .span(pack_sum)
            .value(Value::Text(hex_string(&cx.read(pack_sum).await?))),
    );
    cx.emit(checksum_node(&cx, file, "Index checksum").await?);
    Ok(())
}

async fn fanout_table(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    for i in 0..256usize {
        let v = u32_be(&data, i.saturating_mul(4)).unwrap_or(0);
        cx.push(
            Node::new(format!("{i:02x}"))
                .span(span.sub(to_u64(i).saturating_mul(4), 4))
                .value(Value::UInt { value: v.into(), bits: 32, radix: crate::value::Radix::Dec }),
        )
        .await;
    }
    Ok(())
}

async fn index_objects(
    cx: Cx,
    (file, names, crcs, offsets, count): (Span, Span, Span, Span, u64),
) -> Result<()> {
    cx.set_count(Count::Exact(count));
    let large = offsets.end().saturating_sub(file.offset);
    for i in 0..count {
        let name = names.sub(i.saturating_mul(HASH), HASH);
        let sha = cx.read(name).await?;
        let crc = u32_be(&cx.read(crcs.sub(i.saturating_mul(4), 4)).await?, 0).unwrap_or(0);
        let raw = u32_be(&cx.read(offsets.sub(i.saturating_mul(4), 4)).await?, 0).unwrap_or(0);
        let offset = if raw & 0x8000_0000 != 0 {
            let at = large.saturating_add(u64::from(raw & 0x7fff_ffff).saturating_mul(8));
            u64_be(&cx.read(file.sub_exact(at, 8)?).await?, 0).unwrap_or(0)
        } else {
            raw.into()
        };
        cx.push(
            Node::new(hex_string(&sha))
                .span(name)
                .summary(format!("offset {offset:#x}, CRC-32 {crc:#010x}")),
        )
        .await;
    }
    Ok(())
}

const INDEX_FLAGS: FlagTable = &[
    flag(0x8000, "assume-valid"),
    flag(0x4000, "extended"),
    field(0x3000, 0x1000, "stage 1 (base)"),
    field(0x3000, 0x2000, "stage 2 (ours)"),
    field(0x3000, 0x3000, "stage 3 (theirs)"),
];

const EXTENDED_FLAGS: FlagTable = &[flag(0x4000, "skip-worktree"), flag(0x2000, "intent-to-add")];

const EXTENSIONS: &[(&[u8; 4], &str)] = &[
    (b"TREE", "Cache tree"),
    (b"REUC", "Resolve undo"),
    (b"link", "Split index"),
    (b"UNTR", "Untracked cache"),
    (b"FSMN", "File system monitor cache"),
    (b"EOIE", "End of index entry"),
    (b"IEOT", "Index entry offset table"),
    (b"sdir", "Sparse directory entries"),
];

fn mode_text(mode: u32) -> String {
    format!("{mode:o}")
}

/// One index entry: its span, path and fixed fields.
struct Entry {
    span: Span,
    path: String,
    mode: u32,
    size: u32,
    sha: Vec<u8>,
}

/// Decodes the entry at `pos`; `prev` is the previous path (version 4).
async fn index_entry(cx: &Cx, file: Span, version: u32, pos: u64, prev: &str) -> Result<Entry> {
    let head = cx.read(file.sub_exact(pos, 62)?).await?;
    let flags = u16_be(&head, 60).unwrap_or(0);
    let mut at = pos.saturating_add(62);
    if version >= 3 && flags & 0x4000 != 0 {
        at = at.saturating_add(2);
    }
    let (path, end) = if version >= 4 {
        let window = cx.read_avail(file.sub(at, 10)).await?;
        let (strip, n) = crate::bytes::uleb128(&window)
            .ok_or_else(|| Diagnostic::malformed("bad path prefix").at(file.sub(at, 1)))?;
        let (suffix, span) = cx.cstr(file.sub(at.saturating_add(to_u64(n)), 0x10000)).await?;
        let keep = prev.len().saturating_sub(to_usize(strip));
        let path = format!("{}{suffix}", prev.get(..keep).unwrap_or_default());
        (path, span.end().saturating_sub(file.offset))
    } else {
        let (name, span) = cx.cstr(file.sub(at, 0x10000)).await?;
        let len = span.end().saturating_sub(file.offset).saturating_sub(pos);
        // Entries are NUL-padded to a multiple of 8 bytes.
        let padded = len.checked_next_multiple_of(8).unwrap_or(u64::MAX);
        let padded = if padded == len { len } else { padded };
        (name, pos.saturating_add(padded))
    };
    Ok(Entry {
        span: file.sub(pos, end.saturating_sub(pos)),
        path,
        mode: u32_be(&head, 24).unwrap_or(0),
        size: u32_be(&head, 36).unwrap_or(0),
        sha: head.get(40..60).unwrap_or_default().to_vec(),
    })
}

pub async fn index(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, 12)?).await?;
    let version = u32_be(&head, 4).unwrap_or(0);
    let count = u32_be(&head, 8).unwrap_or(0);
    cx.emit(struct_node("Header", file.sub(0, 12), BE, (), |f, _| {
        f.ascii("Signature", 4).emit()?;
        f.u32("Version").emit()?;
        f.u32("Number of entries").emit()?;
        Ok(())
    }));
    cx.annotate(format!("Git index v{version}, {count} entries"));
    cx.emit(
        Node::new("Entries")
            .summary(format!("{count}"))
            .lazy(index_entries, (file, version, count)),
    );
    cx.emit(
        Node::new("Extensions")
            .lazy(index_extensions, (file, version, count)),
    );
    cx.emit(checksum_node(&cx, file, "Checksum").await?);
    Ok(())
}

async fn index_entries(cx: Cx, (file, version, count): (Span, u32, u32)) -> Result<()> {
    cx.set_count(Count::Exact(count.into()));
    let mut pos = 12u64;
    let mut prev = String::new();
    for _ in 0..count {
        let e = index_entry(&cx, file, version, pos, &prev).await?;
        cx.push(
            Node::new(clip(&e.path, 200))
                .span(e.span)
                .value(Value::Text(hex_string(&e.sha)))
                .summary(format!("{}, {} bytes", mode_text(e.mode), e.size))
                .lazy(entry_fields, (e.span, version)),
        )
        .await;
        pos = e.span.end().saturating_sub(file.offset);
        prev = e.path;
    }
    Ok(())
}

async fn entry_fields(cx: Cx, (span, version): (Span, u32)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("ctime (seconds)").timestamp().emit()?;
    f.u32("ctime (nanoseconds)").emit()?;
    f.u32("mtime (seconds)").timestamp().emit()?;
    f.u32("mtime (nanoseconds)").emit()?;
    f.u32("Device").emit()?;
    f.u32("Inode").emit()?;
    f.u32("Mode").with(|&m, n| n.summary(mode_text(m))).emit()?;
    f.u32("UID").emit()?;
    f.u32("GID").emit()?;
    f.u32("File size").emit()?;
    f.bytes("Object name", HASH).with(|b, n| n.value(Value::Text(hex_string(b)))).emit()?;
    let flags = f
        .u16("Flags")
        .hex()
        .with(|&v, n| {
            let (set, _) = crate::value::decode_flags(INDEX_FLAGS, (v & 0xf000).into());
            let mut text = format!("name length {}", v & 0x0fff);
            for name in set {
                text = format!("{text}, {name}");
            }
            n.summary(text)
        })
        .emit()?;
    if version >= 3 && flags & 0x4000 != 0 {
        f.u16("Extended flags").flags(EXTENDED_FLAGS).emit()?;
    }
    if version >= 4 {
        let window = cx.read_avail(span.sub(f.pos(), 10)).await?;
        if let Some((strip, n)) = crate::bytes::uleb128(&window) {
            f.node(
                Node::new("Prefix strip length")
                    .span(span.sub(f.pos(), to_u64(n)))
                    .value(Value::UInt { value: strip, bits: 64, radix: crate::value::Radix::Dec }),
            );
            f.skip(to_u64(n));
        }
        f.cstr("Path suffix").emit()?;
    } else {
        f.cstr("Path").emit()?;
    }
    Ok(())
}

async fn index_extensions(cx: Cx, (file, version, count): (Span, u32, u32)) -> Result<()> {
    let mut pos = 12u64;
    let mut prev = String::new();
    for _ in 0..count {
        let e = index_entry(&cx, file, version, pos, &prev).await?;
        pos = e.span.end().saturating_sub(file.offset);
        prev = e.path;
        cx.checkpoint().await;
    }
    let end = file.len.saturating_sub(HASH);
    while pos.saturating_add(8) <= end {
        let head = cx.read(file.sub(pos, 8)).await?;
        let sig: [u8; 4] = crate::bytes::array(&head, 0).unwrap_or_default();
        let len = u64::from(u32_be(&head, 4).unwrap_or(0));
        let span = file.sub(pos, len.saturating_add(8));
        let name = EXTENSIONS
            .iter()
            .find(|(s, _)| **s == sig)
            .map_or_else(|| "Extension".to_owned(), |(_, n)| (*n).to_owned());
        let mut node = Node::new(format!("{} ({name})", crate::formats::datakit::fourcc(&sig)))
            .span(span)
            .summary(format!("{len} bytes"));
        if &sig == b"TREE" {
            node = node.lazy(cache_tree, span.tail(8));
        }
        cx.push(node).await;
        pos = pos.saturating_add(8).saturating_add(len);
    }
    Ok(())
}

/// `TREE`: `path NUL entries SP subtrees LF [sha]` records, depth-first.
async fn cache_tree(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut at = 0usize;
    while at < data.len() {
        let rest = data.get(at..).unwrap_or_default();
        let nul = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let lf = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
        if lf <= nul {
            return Err(Diagnostic::malformed("bad cache tree record").at(span.tail(to_u64(at))));
        }
        let path = String::from_utf8_lossy(rest.get(..nul).unwrap_or_default()).into_owned();
        let counts = String::from_utf8_lossy(rest.get(nul.saturating_add(1)..lf).unwrap_or_default()).into_owned();
        let (entries, subtrees) = counts.split_once(' ').unwrap_or((counts.as_str(), "0"));
        let valid = !entries.starts_with('-');
        let mut len = lf.saturating_add(1);
        let mut node = Node::new(if path.is_empty() { "(root)".to_owned() } else { path })
            .summary(format!("{entries} entries, {subtrees} subtrees"));
        if valid {
            let sha = rest.get(len..len.saturating_add(20)).unwrap_or_default();
            node = node.value(Value::Text(hex_string(sha)));
            len = len.saturating_add(20);
        } else {
            node = node.desc("invalidated");
        }
        cx.push(node.span(span.sub(to_u64(at), to_u64(len)))).await;
        at = at.saturating_add(len);
    }
    Ok(())
}
