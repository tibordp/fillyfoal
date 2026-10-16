//! Git storage files: packfiles (`.pack`), pack indexes (`.idx`, version 2)
//! and the index (`.git/index`, `DIRC`, versions 2 to 4).
//!
//! Pack objects record their uncompressed size but not their compressed
//! length, so listing objects means inflating each one (a page at a time);
//! the decoded data is cached and reused when an object is expanded.
//! Commits and tags are shown as headers and message, trees as entries,
//! deltas as copy/insert instructions (and, for ofs-deltas, the object the
//! delta rebuilds from its base), and blobs are dissected as content.
//!
//! Repositories use SHA-1 or SHA-256 object names (`--object-format`);
//! nothing in these files says which, so each file's trailing checksum
//! decides (and, for pack indexes, the table sizes).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::codec::crypto::{Hash, Sha1, Sha256};
use crate::codec::inflate_span;
use crate::cx::{Cx, lock};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::datakit::{clip, hex_string, size};
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

const BE: Endian = Endian::Big;
/// Object name sizes: SHA-1 and SHA-256.
const SHA1_LEN: u64 = 20;
const SHA256_LEN: u64 = 32;

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

fn hash_name(len: u64) -> &'static str {
    if len == SHA256_LEN {
        "SHA-256"
    } else {
        "SHA-1"
    }
}

/// A file's trailing checksum: its length (the object format's hash
/// size) and whether it matched (`None`: too large to check).
#[derive(Clone, Copy, Debug)]
pub(super) struct Trailer {
    pub(super) len: u64,
    valid: Option<bool>,
}

/// Checks the trailing checksum of `file` both as a SHA-1 over all but the
/// last 20 bytes and as a SHA-256 over all but the last 32, in one pass,
/// and settles the hash size by the one that matches; if neither does (or
/// the file is too large to hash), `guess` is taken.
pub(super) async fn trailer(cx: &Cx, file: Span, guess: u64) -> Result<Trailer> {
    let short = file.len.saturating_sub(SHA1_LEN);
    let long = file.len.saturating_sub(SHA256_LEN);
    if short > cx.limits().max_read || file.len < SHA256_LEN {
        return Ok(Trailer {
            len: guess,
            valid: None,
        });
    }
    // Hashed a chunk per read, so each step stays bounded.
    const CHUNK: u64 = 1 << 20;
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut done = 0u64;
    while done < short {
        let n = short.saturating_sub(done).min(CHUNK);
        let data = cx.read(file.sub(done, n)).await?;
        sha1.update(&data);
        let for256 = long.saturating_sub(done).min(n);
        sha256.update(data.get(..to_usize(for256)).unwrap_or_default());
        done = done.saturating_add(n);
    }
    let stored1 = cx.read(file.sub(short, SHA1_LEN)).await?;
    let stored256 = cx.read(file.sub(long, SHA256_LEN)).await?;
    Ok(if sha1.finish() == stored1 {
        Trailer {
            len: SHA1_LEN,
            valid: Some(true),
        }
    } else if sha256.finish() == stored256 {
        Trailer {
            len: SHA256_LEN,
            valid: Some(true),
        }
    } else {
        Trailer {
            len: guess,
            valid: Some(false),
        }
    })
}

/// The node for a file's trailing checksum.
pub(super) async fn checksum_node(
    cx: &Cx,
    file: Span,
    name: &'static str,
    t: Trailer,
) -> Result<Node> {
    let span = file.sub(file.len.saturating_sub(t.len), t.len);
    let stored = cx.read(span).await?;
    let node = Node::new(name)
        .span(span)
        .value(Value::Text(hex_string(&stored)));
    Ok(match t.valid {
        Some(true) => node.summary(format!("valid {}", hash_name(t.len))),
        Some(false) => node.diag(Diagnostic::warning(format!(
            "{} mismatch",
            hash_name(t.len)
        ))),
        None => node.summary(hash_name(t.len)),
    })
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

/// Where a delta's base is.
#[derive(Clone, Debug)]
enum Base {
    None,
    /// An ofs-delta's base: its offset in the pack.
    At(u64),
    /// A ref-delta's base: its object name.
    Named(Vec<u8>),
}

/// An object's header, read from the pack.
#[derive(Clone, Debug)]
struct Header {
    kind: u8,
    size: u64,
    /// Header (and delta base) length.
    len: u64,
    base: Base,
}

/// Reads the header of the object at `pos` of the pack `file`.
async fn read_header(cx: &Cx, file: Span, pos: u64, hash_len: u64) -> Result<Header> {
    let head = cx.read_avail(file.sub(pos, 32)).await?;
    let (kind, size, mut len) = object_header(&head)
        .ok_or_else(|| Diagnostic::malformed("bad object header").at(file.sub(pos, 1)))?;
    let base = match kind {
        6 => {
            let rest = head.get(to_usize(len)..).unwrap_or_default();
            let (offset, n) = delta_offset(rest)
                .ok_or_else(|| Diagnostic::malformed("bad delta offset").at(file.sub(pos, 1)))?;
            len = len.saturating_add(n);
            if offset == 0 || offset > pos {
                return Err(Diagnostic::malformed(format!(
                    "delta base {offset:#x} bytes back from {pos:#x}"
                ))
                .at(file.sub(pos, len)));
            }
            Base::At(pos.saturating_sub(offset))
        }
        7 => {
            let name = cx
                .read(file.sub_exact(pos.saturating_add(len), hash_len)?)
                .await?;
            len = len.saturating_add(hash_len);
            Base::Named(name)
        }
        1..=4 => Base::None,
        _ => {
            return Err(Diagnostic::malformed(format!("object type {kind}")).at(file.sub(pos, 1)));
        }
    };
    Ok(Header {
        kind,
        size,
        len,
        base,
    })
}

/// The pack `file` and the size of its object names.
#[derive(Clone, Copy, Debug)]
struct Pack {
    input: Input,
    hash_len: u64,
}

impl Pack {
    fn file(&self) -> Span {
        self.input.span
    }

    /// Where the objects end (the checksum follows).
    fn body_end(&self) -> u64 {
        self.file().len.saturating_sub(self.hash_len)
    }

    /// The span handed to the inflater for the object whose data starts at
    /// `start` (the same for the listing and the object, so the decoded
    /// data is cached).
    fn stream(&self, start: u64, size: u64) -> Span {
        let end = self.body_end();
        self.file()
            .sub(start, bound(size).min(end.saturating_sub(start)))
    }
}

#[derive(Clone, Debug)]
struct Object {
    pack: Pack,
    /// The object's offset in the pack.
    pos: u64,
    /// The object, from its header to the end of the compressed data.
    span: Span,
    header: Header,
    /// The span handed to the inflater.
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
    // Resume marks: (position, object index, hash size). A resumed run
    // starts in the objects, past the header and checksum emitted first.
    let (mut pos, first, hash_len) = match cx.resume::<(u64, u32, u64)>() {
        Some(state) => state,
        None => {
            cx.emit(struct_node("Header", file.sub(0, 12), BE, (), |f, _| {
                f.ascii("Signature", 4).emit()?;
                f.u32("Version").emit()?;
                f.u32("Number of objects").emit()?;
                Ok(())
            }));
            let t = trailer(&cx, file, SHA1_LEN).await?;
            cx.emit(checksum_node(&cx, file, "Pack checksum", t).await?);
            (12, 0, t.len)
        }
    };
    let p = Pack { input, hash_len };
    let format = if hash_len == SHA256_LEN {
        ", SHA-256"
    } else {
        ""
    };
    cx.annotate(format!(
        "Git pack v{}, {count_object}{format}",
        u32_be(&head, 4).unwrap_or(0),
        count_object = plural(count, "object")
    ));
    let body_end = p.body_end();
    cx.set_count(Count::Exact(u64::from(count).saturating_add(2)));
    for index in first..count {
        if pos >= body_end {
            cx.diag(Diagnostic::truncated(file.sub(pos, 0), 0));
            break;
        }
        let mark = (pos, index, hash_len);
        cx.mark(move || mark);
        let header = read_header(&cx, file, pos, hash_len).await?;
        let base = match &header.base {
            Base::None => String::new(),
            Base::At(at) => format!(", base at {at:#x}"),
            Base::Named(name) => format!(", base {}", hex_string(name)),
        };
        let start = pos.saturating_add(header.len);
        let stream = p.stream(start, header.size);
        let decoded = inflate_span(&cx, stream, true, Some(header.size)).await?;
        let span = file.sub(pos, header.len.saturating_add(decoded.consumed));
        let name = lookup(OBJECT_TYPES, header.kind.into()).unwrap_or("?");
        let mut node = Node::new(format!("{name} at {pos:#x}"))
            .span(span)
            .summary(format!(
                "object {index}, {} → {} bytes{base}",
                decoded.consumed, header.size
            ))
            .lazy(
                object,
                Object {
                    pack: p,
                    pos,
                    span,
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
    let head = cx.block(o.span.sub(0, o.header.len)).await?;
    {
        let mut f = Fields::emitting(&cx, &head, BE);
        let first = f.u8("Type and size").hex().emit()?;
        f.node(Node::new("Type").value(Value::Enum {
            raw: ((first >> 4) & 7).into(),
            bits: 3,
            name: lookup(OBJECT_TYPES, ((first >> 4) & 7).into()).map(Into::into),
        }));
        f.node(Node::new("Size").value(Value::UInt {
            value: o.header.size,
            bits: 64,
            radix: crate::value::Radix::Dec,
        }));
    }
    let decoded = inflate_span(&cx, o.stream, true, Some(o.header.size)).await?;
    cx.emit(
        Node::new("Compressed data")
            .span(o.stream.sub(0, decoded.consumed))
            .summary(format!("zlib, {} bytes", decoded.consumed)),
    );
    let data = decoded.span;
    match o.header.kind {
        6 | 7 => {
            cx.emit(Node::new("Delta").span(data).lazy(delta, data));
            cx.emit(
                Node::new("Resolved object")
                    .summary("the delta applied to its base")
                    .lazy(resolved, (o.pack, o.pos)),
            );
            Ok(())
        }
        kind => show(&cx, o.pack, kind, data).await,
    }
}

/// The content of an object of type `kind` (commit, tree, blob, tag)
/// whose data is `data`.
async fn show(cx: &Cx, pack: Pack, kind: u8, data: Span) -> Result<()> {
    match kind {
        1 | 4 => commit_like(cx, data).await,
        2 => {
            cx.emit(
                Node::new("Entries")
                    .span(data)
                    .lazy(tree_entries, (data, pack.hash_len)),
            );
            Ok(())
        }
        _ => {
            cx.emit(
                Node::new("Content")
                    .span(data)
                    .summary(size(data.len))
                    .lazy(blob, (pack.input, data)),
            );
            Ok(())
        }
    }
}

/// Deltas applied on top of one another at most (git's default for
/// `--depth` is 50).
const MAX_DELTA_DEPTH: usize = 64;

/// The object a delta chain rebuilds.
async fn resolved(cx: Cx, (pack, pos): (Pack, u64)) -> Result<()> {
    let (kind, data) = resolve(&cx, pack, pos).await?;
    let name = lookup(OBJECT_TYPES, kind.into()).unwrap_or("?");
    cx.annotate(format!("{name}, {}", size(data.len)));
    cx.emit(
        Node::new("Object")
            .span(data)
            .value(Value::Enum {
                raw: kind.into(),
                bits: 3,
                name: lookup(OBJECT_TYPES, kind.into()).map(Into::into),
            })
            .summary(size(data.len)),
    );
    show(&cx, pack, kind, data).await
}

/// The delta's transform name in derived-source origins.
const DELTA: &str = "git-delta";

/// Rebuilds the object at `pos`: follows delta bases (ofs-deltas by
/// offset, ref-deltas through the pack's object names, see [`Names`]) back
/// to a whole object, then applies the deltas in turn. Each rebuilt object
/// is kept (keyed by its delta's header), so chains sharing bases rebuild
/// them once. Returns the base object's type and the rebuilt bytes.
async fn resolve(cx: &Cx, pack: Pack, pos: u64) -> Result<(u8, Span)> {
    match walk_chain(cx, pack, pos, Lookup::Scan).await? {
        Walk::Chain(kind, base, chain) => Ok((kind, rebuild(cx, pack, base, &chain).await?)),
        Walk::Missing(at, name) => Err(Diagnostic::unsupported(format!(
            "ref-delta base {} is not in this pack (a thin pack's bases are in the receiving repository)",
            hex_string(&name)
        ))
        .at(pack.file().sub(at, 1))),
    }
}

/// How a chain walk finds ref-delta bases: by scanning the pack for the
/// name as far as needed, or only among the names already found (while
/// scanning, so the scan never recurses into itself).
#[derive(Clone, Copy, PartialEq)]
enum Lookup {
    Scan,
    Known,
}

/// A delta chain: the base object's type, the base (offset and header)
/// and the deltas from the object asked for back to the base, newest
/// first; or the offset of a ref-delta whose base was not found, and its
/// name.
enum Walk {
    Chain(u8, (u64, Header), Vec<(u64, Header)>),
    Missing(u64, Vec<u8>),
}

async fn walk_chain(cx: &Cx, pack: Pack, pos: u64, lookup: Lookup) -> Result<Walk> {
    let file = pack.file();
    let mut chain: Vec<(u64, Header)> = Vec::new();
    let mut at = pos;
    loop {
        let h = read_header(cx, file, at, pack.hash_len).await?;
        let next = match &h.base {
            Base::None => return Ok(Walk::Chain(h.kind, (at, h), chain)),
            Base::At(base) => *base,
            Base::Named(name) => {
                let found = match lookup {
                    Lookup::Scan => find_name(cx, pack, name).await?,
                    Lookup::Known => {
                        names(cx, pack).and_then(|n| lock(&n).found.get(name).copied())
                    }
                };
                match found {
                    Some(base) => base,
                    None => return Ok(Walk::Missing(at, name.clone())),
                }
            }
        };
        if chain.len() >= MAX_DELTA_DEPTH {
            return Err(
                Diagnostic::limit(format!("delta chain deeper than {MAX_DELTA_DEPTH}"))
                    .at(file.sub(pos, 1)),
            );
        }
        chain.push((at, h));
        at = next;
    }
}

/// Applies a walked delta `chain` to its `base`.
async fn rebuild(
    cx: &Cx,
    pack: Pack,
    base: (u64, Header),
    chain: &[(u64, Header)],
) -> Result<Span> {
    let file = pack.file();
    let origin = |at: u64, h: &Header| Origin {
        parent: file.sub(at, h.len),
        transform: DELTA,
    };
    // Start from the newest object already rebuilt, if any.
    let done = chain
        .iter()
        .enumerate()
        .find_map(|(i, (at, h))| Some((i, cx.derived(origin(*at, h))?.span)));
    let (todo, mut data) = match done {
        Some(found) => found,
        None => {
            let (at, h) = base;
            let stream = pack.stream(at.saturating_add(h.len), h.size);
            let span = inflate_span(cx, stream, true, Some(h.size)).await?.span;
            (chain.len(), span)
        }
    };
    for (at, h) in chain.get(..todo).unwrap_or_default().iter().rev() {
        let stream = pack.stream(at.saturating_add(h.len), h.size);
        let delta = inflate_span(cx, stream, true, Some(h.size)).await?;
        let instructions = cx.read(delta.span).await?;
        let source = cx.read(data).await?;
        let out = apply_delta(cx, &instructions, &source, delta.span).await?;
        data = cx
            .add_derived(origin(*at, h), out, delta.span.len, None)?
            .span;
    }
    Ok(data)
}

/// The object names of a pack's objects, found lazily: a ref-delta names
/// its base only by object ID (the hash of `"<type> <size>\0"` and the
/// content), and nothing in the pack maps names to offsets (the `.idx`
/// does, but it is a separate file). So objects are hashed in pack order,
/// one per step, until the name sought turns up; git writes a delta's base
/// before the delta (`write_one` in `pack-objects.c`), so this usually
/// stops short of the end. A delta whose base is not found yet waits for
/// that name and is hashed when it turns up. Shared by every lookup in the
/// pack (`cx.cache`).
#[derive(Default)]
struct Names {
    /// Names found: name → offset in the pack.
    found: BTreeMap<Vec<u8>, u64>,
    /// The next object to hash (offset, and objects left), until the scan
    /// is done.
    next: Option<(u64, u32)>,
    /// Deltas waiting for a base: base name → their offsets.
    waiting: BTreeMap<Vec<u8>, Vec<u64>>,
}

const NAMES: &str = "git-object-names";

/// The pack's name index, if a lookup created one.
fn names(cx: &Cx, pack: Pack) -> Option<Arc<Mutex<Names>>> {
    cx.cached::<Mutex<Names>>(pack.file(), NAMES)
}

/// The offset of the object named `name` in the pack, scanning for it as
/// far as needed (`None`: not in the pack).
async fn find_name(cx: &Cx, pack: Pack, name: &[u8]) -> Result<Option<u64>> {
    let index = match names(cx, pack) {
        Some(index) => index,
        None => {
            let head = cx.read(pack.file().sub_exact(8, 4)?).await?;
            let count = u32_be(&head, 0).unwrap_or(0);
            let index = Arc::new(Mutex::new(Names {
                next: (count > 0).then_some((12, count)),
                ..Names::default()
            }));
            cx.cache(pack.file(), NAMES, index.clone());
            index
        }
    };
    loop {
        let next = {
            let names = lock(&index);
            if let Some(&at) = names.found.get(name) {
                return Ok(Some(at));
            }
            names.next
        };
        let Some((pos, left)) = next else {
            return Ok(None);
        };
        // An object that cannot be read ends the scan (its length, and so
        // the next object's offset, is unknown); one that cannot be
        // rebuilt or hashed is left out.
        let step = name_step_boxed(cx, pack, &index, pos).await;
        let mut names = lock(&index);
        if names.next == next {
            names.next = match step {
                Ok(end) if left > 1 && end > pos && end < pack.body_end() => {
                    Some((end, left.saturating_sub(1)))
                }
                _ => None,
            };
        }
    }
}

/// [`name_step`] boxed: it walks chains (in [`Lookup::Known`] mode, which
/// never scans), but the compiler sees the cycle through [`find_name`].
fn name_step_boxed<'a>(
    cx: &'a Cx,
    pack: Pack,
    index: &'a Mutex<Names>,
    pos: u64,
) -> Pin<Box<dyn Future<Output = Result<u64>> + Send + 'a>> {
    Box::pin(name_step(cx, pack, index, pos))
}

/// Hashes the object at `pos` (and the deltas that were waiting for it),
/// returning where the next object starts.
async fn name_step(cx: &Cx, pack: Pack, index: &Mutex<Names>, pos: u64) -> Result<u64> {
    let h = read_header(cx, pack.file(), pos, pack.hash_len).await?;
    let start = pos.saturating_add(h.len);
    let decoded = inflate_span(cx, pack.stream(start, h.size), true, Some(h.size)).await?;
    let end = start.saturating_add(decoded.consumed);
    // Each object is hashed once, plus once per missing ref-delta base in
    // its chain (at most the chain depth), so the scan stays linear.
    let mut todo = vec![pos];
    while let Some(at) = todo.pop() {
        cx.checkpoint().await;
        let (kind, data) = match walk_chain(cx, pack, at, Lookup::Known).await {
            Ok(Walk::Chain(kind, base, chain)) => match rebuild(cx, pack, base, &chain).await {
                Ok(data) => (kind, data),
                Err(_) => continue,
            },
            Ok(Walk::Missing(_, base)) => {
                lock(index).waiting.entry(base).or_default().push(at);
                continue;
            }
            Err(_) => continue,
        };
        let Ok(name) = object_name(cx, pack, kind, data).await else {
            continue;
        };
        let mut names = lock(index);
        if let Some(waiting) = names.waiting.remove(&name) {
            todo.extend(waiting);
        }
        names.found.entry(name).or_insert(at);
    }
    Ok(end)
}

/// The object name of an object of type `kind` whose content is `data`.
async fn object_name(cx: &Cx, pack: Pack, kind: u8, data: Span) -> Result<Vec<u8>> {
    if pack.hash_len == SHA256_LEN {
        hash_object::<Sha256>(cx, kind, data).await
    } else {
        hash_object::<Sha1>(cx, kind, data).await
    }
}

async fn hash_object<H: Hash>(cx: &Cx, kind: u8, data: Span) -> Result<Vec<u8>> {
    // Hashed a chunk per read, so each step stays bounded.
    const CHUNK: u64 = 1 << 16;
    let mut h = H::new();
    let name = lookup(OBJECT_TYPES, kind.into()).unwrap_or("?");
    h.update(format!("{name} {}\0", data.len).as_bytes());
    let mut done = 0u64;
    while done < data.len {
        let chunk = cx.read(data.sub(done, CHUNK)).await?;
        if chunk.is_empty() {
            break;
        }
        h.update(&chunk);
        // Roughly a microsecond of hashing per 256 bytes.
        cx.charge(to_u64(chunk.len()) / 256).await;
        done = done.saturating_add(to_u64(chunk.len()));
    }
    Ok(h.finish())
}

/// Applies git delta `instructions` (`patch-delta.c`) to `source`.
async fn apply_delta(cx: &Cx, instructions: &[u8], source: &[u8], at: Span) -> Result<Vec<u8>> {
    let bad = |what: &str| Diagnostic::malformed(format!("delta: {what}")).at(at);
    let (src_size, n) = crate::bytes::uleb128(instructions).ok_or_else(|| bad("bad size"))?;
    let rest = instructions.get(n..).unwrap_or_default();
    let (dst_size, m) = crate::bytes::uleb128(rest).ok_or_else(|| bad("bad size"))?;
    if src_size != to_u64(source.len()) {
        return Err(bad(&format!(
            "source size {src_size}, base has {}",
            source.len()
        )));
    }
    if dst_size > cx.limits().max_derived {
        return Err(Diagnostic::limit(format!("delta target of {dst_size} bytes")).at(at));
    }
    let mut ops = rest.get(m..).unwrap_or_default().iter();
    let mut out = Vec::new();
    // Bytes copied since the last checkpoint.
    let mut paced = 0usize;
    while let Some(&op) = ops.next() {
        if op & 0x80 != 0 {
            let mut offset = 0u64;
            let mut len = 0u64;
            for bit in 0..7u32 {
                if op & (1 << bit) != 0 {
                    let b = u64::from(*ops.next().ok_or_else(|| bad("truncated copy"))?);
                    if bit < 4 {
                        offset |= b.checked_shl(bit.saturating_mul(8)).unwrap_or(0);
                    } else {
                        len |= b
                            .checked_shl(bit.saturating_sub(4).saturating_mul(8))
                            .unwrap_or(0);
                    }
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            let piece = source
                .get(to_usize(offset)..to_usize(offset.saturating_add(len)))
                .ok_or_else(|| bad("copy past the end of the base"))?;
            out.extend_from_slice(piece);
            paced = paced.saturating_add(piece.len());
        } else if op == 0 {
            return Err(bad("opcode 0"));
        } else {
            for _ in 0..op {
                out.push(*ops.next().ok_or_else(|| bad("truncated insert"))?);
            }
            paced = paced.saturating_add(usize::from(op));
        }
        if to_u64(out.len()) > dst_size {
            return Err(bad("writes past the target size"));
        }
        if paced >= 1 << 16 {
            paced = 0;
            cx.checkpoint().await;
        }
    }
    if to_u64(out.len()) != dst_size {
        return Err(bad(&format!("target size {dst_size}, wrote {}", out.len())));
    }
    Ok(out)
}

async fn blob(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    crate::formats::dissect_or_data(cx, input.nested(data)).await
}

/// Commit and tag objects: header lines, a blank line, the message. A
/// header value spans several lines when the following lines start with a
/// space (`gpgsig`, `mergetag`): git strips that space and joins the lines
/// with newlines (`commit.c`, `read_commit_extra_header_lines`).
async fn commit_like(cx: &Cx, data: Span) -> Result<()> {
    let bytes = cx.read(data.sub(0, 0x10000)).await?;
    let mut at = 0usize;
    let mut message_at = None;
    // The header being collected: key, value, start and end offsets.
    let mut pending: Option<(String, String, usize, usize)> = None;
    for line in bytes.split(|&b| b == b'\n') {
        let len = line.len();
        let end = at.saturating_add(len);
        if line.is_empty() {
            message_at = Some(at.saturating_add(1));
            break;
        }
        if let (Some(rest), Some((_, value, _, last))) = (line.strip_prefix(b" "), pending.as_mut())
        {
            value.push('\n');
            value.push_str(&String::from_utf8_lossy(rest));
            *last = end;
        } else {
            if let Some((key, value, start, last)) = pending.take() {
                cx.emit(commit_header(data, key, &value, start, last));
            }
            let text = String::from_utf8_lossy(line).into_owned();
            let (key, value) = text.split_once(' ').unwrap_or((text.as_str(), ""));
            pending = Some((key.to_owned(), value.to_owned(), at, end));
        }
        at = end.saturating_add(1);
    }
    if let Some((key, value, start, last)) = pending.take() {
        cx.emit(commit_header(data, key, &value, start, last));
    }
    if let Some(m) = message_at {
        let span = data.tail(to_u64(m));
        let text = String::from_utf8_lossy(bytes.get(m..).unwrap_or_default()).into_owned();
        cx.emit(
            Node::new("Message")
                .span(span)
                .value(Value::Text(clip(text.trim_end(), 4000))),
        );
    }
    Ok(())
}

/// One commit or tag header (`start..end` in `data`, continuation lines
/// included).
fn commit_header(data: Span, key: String, value: &str, start: usize, end: usize) -> Node {
    let span = data.sub(to_u64(start), to_u64(end.saturating_sub(start)));
    let person = matches!(key.as_str(), "author" | "committer" | "tagger");
    let mut node = Node::new(key).span(span);
    // author/committer/tagger: "Name <email> 1234567890 +0000"
    if person && let Some((who, when)) = value.rsplit_once("> ") {
        let seconds = when
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<i64>().ok());
        node = node.value(Value::Text(format!("{who}>")));
        if let Some(s) = seconds {
            node = node.summary(format!(
                "{} {}",
                crate::render::value(&Value::Timestamp { unix_seconds: s }),
                when.split_whitespace().nth(1).unwrap_or_default()
            ));
        }
    } else {
        node = node.value(Value::Text(clip(value, 4000)));
        let lines = value.lines().count();
        if lines > 1 {
            node = node.summary(plural(lines, "line"));
        }
    }
    node
}

/// Tree entries: `mode SP name NUL` and the entry's object name.
async fn tree_entries(cx: Cx, (data, hash_len): (Span, u64)) -> Result<()> {
    let bytes = cx.read(data).await?;
    let hash = to_usize(hash_len);
    let mut at = 0usize;
    while at < bytes.len() {
        let rest = bytes.get(at..).unwrap_or_default();
        let Some(nul) = rest.iter().position(|&b| b == 0) else {
            return Err(Diagnostic::malformed("unterminated tree entry").at(data.tail(to_u64(at))));
        };
        let head = String::from_utf8_lossy(rest.get(..nul).unwrap_or_default()).into_owned();
        let (mode, name) = head.split_once(' ').unwrap_or(("?", head.as_str()));
        let len = nul.saturating_add(1).saturating_add(hash);
        let sha = rest.get(nul.saturating_add(1)..len).unwrap_or_default();
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
        cx.emit(
            Node::new(name)
                .span(data.sub(to_u64(at), to_u64(n)))
                .value(Value::UInt {
                    value: v,
                    bits: 64,
                    radix: crate::value::Radix::Dec,
                }),
        );
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
                        len |= b
                            .checked_shl(bit.saturating_sub(4).saturating_mul(8))
                            .unwrap_or(0);
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

/// The object name size of a version 2 pack index of `len` bytes holding
/// `count` objects: `8 + 1024 + count * (H + 8) + 8 * large + 2 * H`
/// bytes, with at most `count` large offsets. `None` when both sizes fit
/// (or neither does).
fn index_hash_len(len: u64, count: u64) -> Option<u64> {
    let fits = |h: u64| {
        let fixed = count
            .checked_mul(h.checked_add(8)?)?
            .checked_add(1032)?
            .checked_add(h.checked_mul(2)?)?;
        let large = len.checked_sub(fixed)?;
        (large.is_multiple_of(8) && large / 8 <= count).then_some(h)
    };
    match (fits(SHA1_LEN), fits(SHA256_LEN)) {
        (Some(h), None) | (None, Some(h)) => Some(h),
        _ => None,
    }
}

pub async fn pack_index(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let fanout = file.sub_exact(8, 1024)?;
    let table = cx.read(fanout).await?;
    let count = u64::from(u32_be(&table, 1020).unwrap_or(0));
    let t = trailer(
        &cx,
        file,
        index_hash_len(file.len, count).unwrap_or(SHA1_LEN),
    )
    .await?;
    let hash = t.len;
    cx.emit(struct_node("Header", file.sub(0, 8), BE, (), |f, _| {
        f.bytes("Magic", 4).emit()?;
        f.u32("Version").emit()?;
        Ok(())
    }));
    cx.annotate(format!(
        "Git pack index v2, {count_object}{}",
        if hash == SHA256_LEN { ", SHA-256" } else { "" },
        count_object = plural(count, "object")
    ));
    cx.emit(
        Node::new("Fan-out table")
            .span(fanout)
            .summary("cumulative object counts by first byte")
            .lazy(fanout_table, fanout),
    );
    let names = file.sub_exact(1032, count.saturating_mul(hash))?;
    let crcs = file.sub_exact(
        names.end().saturating_sub(file.offset),
        count.saturating_mul(4),
    )?;
    let offsets = file.sub_exact(
        crcs.end().saturating_sub(file.offset),
        count.saturating_mul(4),
    )?;
    cx.emit(
        Node::new("Objects")
            .span(names)
            .summary(format!("{count}"))
            .lazy(index_objects, (file, names, crcs, offsets, count, hash)),
    );
    cx.emit(Node::new("CRC-32 table").span(crcs));
    cx.emit(Node::new("Offset table").span(offsets));
    let trailer_at = file.len.saturating_sub(hash.saturating_mul(2));
    let large_at = offsets.end().saturating_sub(file.offset);
    if trailer_at > large_at {
        cx.emit(
            Node::new("Large offsets")
                .span(file.sub(large_at, trailer_at.saturating_sub(large_at))),
        );
    }
    let pack_sum = file.sub(trailer_at, hash);
    cx.emit(
        Node::new("Pack checksum")
            .span(pack_sum)
            .value(Value::Text(hex_string(&cx.read(pack_sum).await?))),
    );
    cx.emit(checksum_node(&cx, file, "Index checksum", t).await?);
    Ok(())
}

async fn fanout_table(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    for i in 0..256usize {
        let v = u32_be(&data, i.saturating_mul(4)).unwrap_or(0);
        cx.push(
            Node::new(format!("{i:02x}"))
                .span(span.sub(to_u64(i).saturating_mul(4), 4))
                .value(Value::UInt {
                    value: v.into(),
                    bits: 32,
                    radix: crate::value::Radix::Dec,
                }),
        )
        .await;
    }
    Ok(())
}

async fn index_objects(
    cx: Cx,
    (file, names, crcs, offsets, count, hash): (Span, Span, Span, Span, u64, u64),
) -> Result<()> {
    cx.set_count(Count::Exact(count));
    let large = offsets.end().saturating_sub(file.offset);
    // Resume marks: the next index (each entry is at a fixed place).
    let first = cx.resume::<u64>().unwrap_or(0);
    for i in first..count {
        cx.mark(move || i);
        let name = names.sub(i.saturating_mul(hash), hash);
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

/// The index `file`: its version, entry count and object name size.
#[derive(Clone, Copy, Debug)]
struct Dirc {
    file: Span,
    version: u32,
    count: u32,
    hash_len: u64,
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
/// The fixed part is 40 bytes of stat data, the object name and 2 bytes
/// of flags.
async fn index_entry(cx: &Cx, d: &Dirc, pos: u64, prev: &str) -> Result<Entry> {
    let file = d.file;
    let fixed = d.hash_len.saturating_add(42);
    let head = cx.read(file.sub_exact(pos, fixed)?).await?;
    let flags = u16_be(&head, to_usize(fixed.saturating_sub(2))).unwrap_or(0);
    let mut at = pos.saturating_add(fixed);
    if d.version >= 3 && flags & 0x4000 != 0 {
        at = at.saturating_add(2);
    }
    let (path, end) = if d.version >= 4 {
        let window = cx.read_avail(file.sub(at, 10)).await?;
        let (strip, n) = crate::bytes::uleb128(&window)
            .ok_or_else(|| Diagnostic::malformed("bad path prefix").at(file.sub(at, 1)))?;
        let (suffix, span) = cx
            .cstr(file.sub(at.saturating_add(to_u64(n)), 0x10000))
            .await?;
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
        sha: head
            .get(40..to_usize(fixed.saturating_sub(2)))
            .unwrap_or_default()
            .to_vec(),
    })
}

pub async fn index(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, 12)?).await?;
    let version = u32_be(&head, 4).unwrap_or(0);
    let count = u32_be(&head, 8).unwrap_or(0);
    let t = trailer(&cx, file, SHA1_LEN).await?;
    let d = Dirc {
        file,
        version,
        count,
        hash_len: t.len,
    };
    cx.emit(struct_node("Header", file.sub(0, 12), BE, (), |f, _| {
        f.ascii("Signature", 4).emit()?;
        f.u32("Version").emit()?;
        f.u32("Number of entries").emit()?;
        Ok(())
    }));
    cx.annotate(format!(
        "Git index v{version}, {count_entry}{}",
        if t.len == SHA256_LEN { ", SHA-256" } else { "" },
        count_entry = plural(count, "entry")
    ));
    cx.emit(
        Node::new("Entries")
            .summary(format!("{count}"))
            .lazy(index_entries, d),
    );
    cx.emit(Node::new("Extensions").lazy(index_extensions, d));
    cx.emit(checksum_node(&cx, file, "Checksum", t).await?);
    Ok(())
}

async fn index_entries(cx: Cx, d: Dirc) -> Result<()> {
    cx.set_count(Count::Exact(d.count.into()));
    // Resume marks: (position, entry index, previous path); version 4
    // paths are compressed against the previous one.
    let (mut pos, first, mut prev) =
        cx.resume::<(u64, u32, String)>()
            .unwrap_or((12, 0, String::new()));
    for i in first..d.count {
        cx.mark(|| (pos, i, prev.clone()));
        let e = index_entry(&cx, &d, pos, &prev).await?;
        cx.push(
            Node::new(clip(&e.path, 200))
                .span(e.span)
                .value(Value::Text(hex_string(&e.sha)))
                .summary(format!("{}, {} bytes", mode_text(e.mode), e.size))
                .lazy(entry_fields, (e.span, d.version, d.hash_len)),
        )
        .await;
        pos = e.span.end().saturating_sub(d.file.offset);
        prev = e.path;
    }
    Ok(())
}

async fn entry_fields(cx: Cx, (span, version, hash_len): (Span, u32, u64)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("ctime (seconds)").timestamp().emit()?;
    f.u32("ctime (nanoseconds)").emit()?;
    f.u32("mtime (seconds)").timestamp().emit()?;
    f.u32("mtime (nanoseconds)").emit()?;
    f.u32("Device").emit()?;
    f.u32("Inode").emit()?;
    f.u32("Mode").oct().emit()?;
    f.u32("UID").emit()?;
    f.u32("GID").emit()?;
    f.u32("File size").emit()?;
    f.bytes("Object name", hash_len)
        .with(|b, n| n.value(Value::Text(hex_string(b))))
        .emit()?;
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
                    .value(Value::UInt {
                        value: strip,
                        bits: 64,
                        radix: crate::value::Radix::Dec,
                    }),
            );
            f.skip(to_u64(n));
        }
        f.cstr("Path suffix").emit()?;
    } else {
        f.cstr("Path").emit()?;
    }
    Ok(())
}

async fn index_extensions(cx: Cx, d: Dirc) -> Result<()> {
    let file = d.file;
    let mut pos = 12u64;
    let mut prev = String::new();
    for _ in 0..d.count {
        let e = index_entry(&cx, &d, pos, &prev).await?;
        pos = e.span.end().saturating_sub(file.offset);
        prev = e.path;
        cx.checkpoint().await;
    }
    let end = file.len.saturating_sub(d.hash_len);
    while pos.saturating_add(8) <= end {
        let head = cx.read(file.sub(pos, 8)).await?;
        let sig: [u8; 4] = crate::bytes::array(&head, 0).unwrap_or_default();
        let len = u64::from(u32_be(&head, 4).unwrap_or(0));
        let span = file.sub(pos, len.saturating_add(8));
        let name = EXTENSIONS
            .iter()
            .find(|(s, _)| **s == sig)
            .map_or_else(|| "Extension".to_owned(), |(_, n)| (*n).to_owned());
        let mut node = Node::new(format!(
            "{} ({name})",
            crate::formats::util::datakit::fourcc(&sig)
        ))
        .span(span)
        .summary(format!("{len} bytes"));
        if &sig == b"TREE" {
            node = node.lazy(cache_tree, (span.tail(8), d.hash_len));
        }
        cx.push(node).await;
        pos = pos.saturating_add(8).saturating_add(len);
    }
    Ok(())
}

/// `TREE`: `path NUL entries SP subtrees LF [object name]` records,
/// depth-first.
async fn cache_tree(cx: Cx, (span, hash_len): (Span, u64)) -> Result<()> {
    let data = cx.read(span).await?;
    let hash = to_usize(hash_len);
    let mut at = 0usize;
    while at < data.len() {
        let rest = data.get(at..).unwrap_or_default();
        let nul = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let lf = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
        if lf <= nul {
            return Err(Diagnostic::malformed("bad cache tree record").at(span.tail(to_u64(at))));
        }
        let path = String::from_utf8_lossy(rest.get(..nul).unwrap_or_default()).into_owned();
        let counts =
            String::from_utf8_lossy(rest.get(nul.saturating_add(1)..lf).unwrap_or_default())
                .into_owned();
        let (entries, subtrees) = counts.split_once(' ').unwrap_or((counts.as_str(), "0"));
        let valid = !entries.starts_with('-');
        let mut len = lf.saturating_add(1);
        let mut node = Node::new(if path.is_empty() {
            "(root)".to_owned()
        } else {
            path
        })
        .summary(format!(
            "{entries_entry}, {subtrees} subtrees",
            entries_entry = plural(entries, "entry")
        ));
        if valid {
            let sha = rest.get(len..len.saturating_add(hash)).unwrap_or_default();
            node = node.value(Value::Text(hex_string(sha)));
            len = len.saturating_add(hash);
        } else {
            node = node.desc("invalidated");
        }
        cx.push(node.span(span.sub(to_u64(at), to_u64(len)))).await;
        at = at.saturating_add(len);
    }
    Ok(())
}
