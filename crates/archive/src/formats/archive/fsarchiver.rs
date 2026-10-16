//! FSArchiver archives (`.fsa`, `fsarchiver savefs` / `savedir`).
//!
//! An archive is a sequence of headers, each a 4-byte magic, the archive id,
//! a filesystem index (0xffff for none), the size of a dictionary, the
//! dictionary and its Fletcher-32 checksum. A dictionary is a count and
//! that many items: a type (1-4: unsigned integers of 1 to 8 bytes, 5: raw
//! data, 6: a NUL-terminated string), a section (0: standard attributes,
//! 1: extended attributes, 2: Windows attributes), a 16-bit key and the
//! data's size, all little-endian. What the keys mean depends on the
//! header:
//!
//! - `FsA0` / `FsAE`: volume header and footer (every file of a split
//!   archive starts and ends with them);
//! - `ArCh`: the archive header (format version, creating version, id,
//!   creation time, label, type, compression and encryption);
//! - `FsIn`, `FsYs`: a saved filesystem's description and start
//!   (`savefs` archives);
//! - `DiRs`: directory information;
//! - `ObJt`: a filesystem object (path, type, mode, owner, times, size;
//!   for regular files the MD5 of the content);
//! - `BlKh`: a block header, followed by the block's data (compressed with
//!   the algorithm it names, then possibly encrypted), and `FiLf`, the
//!   footer after the blocks of a file stored in blocks of its own (with
//!   the content's MD5);
//! - `DaEn`: the end of a filesystem's (or the directories') data.
//!
//! Files smaller than a block are packed together: their objects come
//! first, each with its offset in the shared block that follows them.
//! Larger files are an object, their own blocks and a footer; the listing
//! groups those, and their content is the blocks decoded on demand, one
//! piece per block. Blocks decode with the existing codecs: LZO1X, zlib
//! ("gzip"), bzip2, xz ("lzma"), raw LZ4 blocks and zstd; Blowfish
//! encryption is not supported (its blocks are listed, not decoded), nor is
//! the MD5 of file contents checked.
//!
//! Written from archives made by fsarchiver 0.8.8 (`savedir` with every
//! compression algorithm and with encryption, and `savefs` of an ext2
//! filesystem; fixtures in `tests/fixtures/external/fsarchiver/`): the
//! header magics, the dictionary encoding and the Fletcher-32 checksums
//! were worked out from those archives, the meaning of the keys from what
//! they hold there and from memory of fsarchiver's sources (none were read
//! or copied). Keys whose meaning was not established are shown by number.

use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::unix_mode;
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{enumv, hex, text, uint};
use crate::formats::{Codec, Format, Head, Input, Probe, content, dissect_or_data};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value};

pub static FORMAT: Format = Format {
    name: "fsarchiver",
    title: "FSArchiver archive",
    extensions: &["fsa"],
    mime: "application/x-fsarchiver",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Magic, archive id, filesystem index, dictionary size.
const FIXED: u64 = 14;
/// Dictionaries larger than this are refused (an encrypted archive's
/// header, the largest seen, is about 4 KiB).
const MAX_DICO: u64 = 1 << 20;
/// Bytes walked per step when checksumming block data.
const CHUNK: u64 = 1 << 16;

const MAGICS: &[(&[u8; 4], &str)] = &[
    (b"FsA0", "Volume header"),
    (b"FsAE", "Volume footer"),
    (b"ArCh", "Archive header"),
    (b"FsIn", "Filesystem info"),
    (b"FsYs", "Filesystem start"),
    (b"DiRs", "Directories info"),
    (b"ObJt", "Object"),
    (b"BlKh", "Block"),
    (b"FiLf", "File footer"),
    (b"DaEn", "Data end"),
];

const ARCHIVE_TYPES: EnumTable = &[(1, "filesystems"), (2, "flat files")];
const COMPRESSION: EnumTable = &[
    (1, "none"),
    (2, "lzo"),
    (3, "gzip"),
    (4, "bzip2"),
    (5, "lzma"),
    (6, "lz4"),
    (7, "zstd"),
];
const ENCRYPTION: EnumTable = &[(1, "none"), (2, "blowfish")];
const OBJECT_TYPES: EnumTable = &[
    (1, "directory"),
    (2, "symbolic link"),
    (3, "hard link"),
    (4, "character device"),
    (5, "block device"),
    (6, "FIFO"),
    (7, "socket"),
    (8, "regular file (own blocks)"),
    (9, "regular file (shared block)"),
];

/// How a key's value is shown.
#[derive(Clone, Copy)]
enum Show {
    Plain,
    Hex,
    Time,
    Mode,
    Size,
    Enum(EnumTable),
}

/// Names of the keys of section 0, per header.
fn key_name(magic: &[u8; 4], key: u16) -> Option<(&'static str, Show)> {
    use Show::*;
    Some(match (magic, key) {
        (b"FsA0" | b"FsAE", 0) => ("Volume number", Plain),
        (b"FsA0" | b"FsAE", 1) => ("Archive id", Hex),
        (b"FsA0", 2) => ("File format", Plain),
        (b"FsA0", 3) => ("Created with", Plain),
        (b"FsAE", 2) => ("Last volume", Plain),
        (b"ArCh", 1) => ("File format", Plain),
        (b"ArCh", 2) => ("Created with", Plain),
        (b"ArCh", 3) => ("Archive id", Hex),
        (b"ArCh", 4) => ("Created", Time),
        (b"ArCh", 5) => ("Label", Plain),
        (b"ArCh", 6) => ("Archive type", Enum(ARCHIVE_TYPES)),
        (b"ArCh", 7) => ("Filesystems", Plain),
        (b"ArCh", 8) => ("Compression", Enum(COMPRESSION)),
        (b"ArCh", 9) => ("Compression level", Plain),
        (b"ArCh", 10) => ("Encryption", Enum(ENCRYPTION)),
        (b"ArCh", 11) => ("Password check (MD5)", Plain),
        (b"ArCh", 12) => ("Password check (encrypted)", Plain),
        (b"ArCh", 13) => ("fsarchiver level (-z / -Z)", Plain),
        (b"ArCh", 14) => ("Minimum fsarchiver version", Hex),
        (b"ArCh", 15) => ("Has directories info", Plain),
        (b"FsIn", 1) => ("Filesystem", Plain),
        (b"FsIn", 2) => ("Mount point", Plain),
        (b"FsIn", 3) => ("Total bytes", Size),
        (b"FsIn", 4) => ("Used bytes", Size),
        (b"FsIn", 5) => ("Label", Plain),
        (b"FsIn", 6) => ("UUID", Plain),
        (b"FsIn", 9) => ("Mount options", Plain),
        (b"FsIn", 25) => ("Minimum fsarchiver version", Hex),
        (b"FsIn", 27) => ("Device", Plain),
        (b"ObJt", 1) => ("Object id", Plain),
        (b"ObJt", 2) => ("Path", Plain),
        (b"ObJt", 3) => ("Object type", Enum(OBJECT_TYPES)),
        (b"ObJt", 4) => ("Link target", Plain),
        (b"ObJt", 5) => ("Hard link target", Plain),
        (b"ObJt", 6) => ("Device number", Hex),
        (b"ObJt", 7) => ("Mode", Mode),
        (b"ObJt", 8) => ("Size", Size),
        (b"ObJt", 9) => ("User id", Plain),
        (b"ObJt", 10) => ("Group id", Plain),
        (b"ObJt", 11) => ("Accessed", Time),
        (b"ObJt", 12) => ("Modified", Time),
        (b"ObJt", 13) => ("MD5", Plain),
        (b"ObJt", 14) => ("Files in the shared block", Plain),
        (b"ObJt", 15) => ("Offset in the shared block", Hex),
        (b"BlKh", 1) => ("Decoded size", Size),
        (b"BlKh", 2) => ("Offset in the file", Hex),
        (b"BlKh", 3) => ("Compression", Enum(COMPRESSION)),
        (b"BlKh", 4) => ("Encryption", Enum(ENCRYPTION)),
        (b"BlKh", 5) => ("Compressed size", Size),
        (b"BlKh", 6) => ("Stored size", Size),
        (b"BlKh", 7) => ("Data checksum", Hex),
        (b"FiLf", 1) => ("MD5", Plain),
        _ => return None,
    })
}

fn probe(h: &Head) -> bool {
    // "FsA0", then a dictionary of a handful of well-formed items.
    if !h.starts_with(b"FsA0") {
        return false;
    }
    let u16_at = |o: usize| crate::bytes::u16_le(h.data, o);
    let size = crate::bytes::u32_le(h.data, 10);
    let (Some(size), Some(count)) = (size, u16_at(14)) else {
        return false;
    };
    if !(8..=4096).contains(&size) || count == 0 || count > 64 {
        return false;
    }
    let (Some(&kind), Some(len)) = (h.data.get(16), u16_at(20)) else {
        return false;
    };
    (1..=6).contains(&kind) && u32::from(len).saturating_add(8) <= size
}

/// One dictionary item.
#[derive(Clone, Debug)]
struct Item {
    kind: u8,
    section: u8,
    key: u16,
    data: Vec<u8>,
    span: Span,
}

impl Item {
    fn uint(&self) -> Option<u64> {
        (1..=4).contains(&self.kind).then(|| {
            self.data
                .iter()
                .rev()
                .fold(0u64, |acc, &b| acc.wrapping_shl(8) | u64::from(b))
        })
    }

    fn string(&self) -> String {
        crate::text::until_nul(&self.data)
    }
}

/// A header, parsed.
#[derive(Clone, Debug)]
struct Header {
    magic: [u8; 4],
    archive: u32,
    fs: u16,
    items: Vec<Item>,
    checksum: u32,
    computed: u32,
    /// Fixed fields, dictionary and checksum.
    span: Span,
}

impl Header {
    fn get(&self, key: u16) -> Option<&Item> {
        self.items.iter().find(|i| i.section == 0 && i.key == key)
    }

    fn uint(&self, key: u16) -> Option<u64> {
        self.get(key).and_then(Item::uint)
    }

    fn string(&self, key: u16) -> Option<String> {
        self.get(key).map(Item::string)
    }

    fn name(&self) -> &'static str {
        MAGICS
            .iter()
            .find(|(m, _)| **m == self.magic)
            .map_or("Header", |(_, n)| n)
    }
}

/// FSArchiver's Fletcher-32 (over bytes, sums reduced every 360 of them).
#[derive(Clone, Copy)]
struct Fletcher {
    a: u32,
    b: u32,
}

impl Fletcher {
    fn new() -> Self {
        Fletcher {
            a: 0xffff,
            b: 0xffff,
        }
    }

    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(360) {
            for &v in chunk {
                self.a = self.a.wrapping_add(u32::from(v));
                self.b = self.b.wrapping_add(self.a);
            }
            self.a = (self.a & 0xffff).wrapping_add(self.a >> 16);
            self.b = (self.b & 0xffff).wrapping_add(self.b >> 16);
        }
    }

    fn value(self) -> u32 {
        let a = (self.a & 0xffff).wrapping_add(self.a >> 16);
        let b = (self.b & 0xffff).wrapping_add(self.b >> 16);
        (b << 16) | (a & 0xffff)
    }
}

/// Reads the header at `pos` of `region`; `None` at the end of the region.
async fn read_header(cx: &Cx, region: Span, pos: u64) -> Result<Option<Header>> {
    if pos >= region.len {
        return Ok(None);
    }
    let fixed = region.sub(pos, FIXED);
    let raw = cx.read(fixed).await?;
    let magic: [u8; 4] = raw
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .unwrap_or_default();
    if !magic.iter().all(u8::is_ascii_alphanumeric) {
        return Err(Diagnostic::malformed(format!(
            "no header at offset {pos:#x} (found {})",
            crate::text::latin1(&magic).escape_debug()
        ))
        .at(fixed));
    }
    let archive = crate::bytes::u32_le(&raw, 4).unwrap_or(0);
    let fs = crate::bytes::u16_le(&raw, 8).unwrap_or(0);
    let size = u64::from(crate::bytes::u32_le(&raw, 10).unwrap_or(0));
    if size > MAX_DICO {
        return Err(Diagnostic::unsupported(format!("dictionary of {size} bytes")).at(fixed));
    }
    let dico_span = region.sub_exact(pos.saturating_add(FIXED), size.saturating_add(4))?;
    let dico = cx.read(dico_span).await?;
    let body_len = crate::bytes::to_usize(size);
    let body = dico.get(..body_len).unwrap_or_default();
    let checksum = crate::bytes::u32_le(&dico, body_len).unwrap_or(0);
    let mut f = Fletcher::new();
    f.update(body);
    let count = crate::bytes::u16_le(body, 0).unwrap_or(0);
    let mut items = Vec::new();
    let mut at = 2usize;
    for _ in 0..count {
        let Some(h) = body.get(at..at.saturating_add(6)) else {
            break;
        };
        let len = usize::from(crate::bytes::u16_le(h, 4).unwrap_or(0));
        let start = at.saturating_add(6);
        let Some(data) = body.get(start..start.saturating_add(len)) else {
            break;
        };
        items.push(Item {
            kind: h.first().copied().unwrap_or(0),
            section: h.get(1).copied().unwrap_or(0),
            key: crate::bytes::u16_le(h, 2).unwrap_or(0),
            data: data.to_vec(),
            span: dico_span.sub(
                crate::bytes::to_u64(at),
                crate::bytes::to_u64(6usize.saturating_add(len)),
            ),
        });
        at = start.saturating_add(len);
    }
    cx.charge(size / 1024).await;
    Ok(Some(Header {
        magic,
        archive,
        fs,
        items,
        checksum,
        computed: f.value(),
        span: region.sub(pos, FIXED.saturating_add(size).saturating_add(4)),
    }))
}

/// A block: its header and where its data is.
#[derive(Clone, Debug)]
struct Block {
    header: Header,
    data: Span,
}

impl Block {
    fn codec(&self) -> std::result::Result<Codec, Diagnostic> {
        let compression = self.header.uint(3).unwrap_or(0);
        if self.header.uint(4).unwrap_or(1) != 1 {
            return Err(Diagnostic::unsupported("Blowfish-encrypted block"));
        }
        Ok(match compression {
            1 => Codec::Stored,
            2 => Codec::Lzo1x,
            3 => Codec::Zlib,
            4 => Codec::Bzip2,
            5 => Codec::Xz,
            6 => Codec::Lz4Block,
            7 => Codec::Zstd,
            other => {
                return Err(Diagnostic::unsupported(format!(
                    "compression algorithm {other}"
                )));
            }
        })
    }

    fn decoded(&self) -> u64 {
        self.header.uint(1).unwrap_or(0)
    }

    fn summary(&self) -> String {
        let algo = crate::formats::util::val::name_or(
            COMPRESSION,
            self.header.uint(3).unwrap_or(0),
            "algorithm ",
        );
        let enc = if self.header.uint(4).unwrap_or(1) == 2 {
            ", encrypted"
        } else {
            ""
        };
        format!(
            "{algo}{enc}, {} → {}",
            size(self.data.len),
            size(self.decoded())
        )
    }
}

/// Reads the data after a block header.
fn block_at(region: Span, header: Header) -> Result<Block> {
    let stored = header.uint(6).or_else(|| header.uint(5)).unwrap_or(0);
    let data = region.sub_exact(header.span.end().saturating_sub(region.offset), stored)?;
    Ok(Block { header, data })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let region = input.span;
    // The volume and archive headers, for the summary.
    if cx.resume::<(u64, u64)>().is_none()
        && let Some(volume) = read_header(&cx, region, 0).await?
        && let Some(main) = read_header(&cx, region, volume.span.len).await?
        && main.magic == *b"ArCh"
    {
        let kind =
            crate::formats::util::val::name_or(ARCHIVE_TYPES, main.uint(6).unwrap_or(0), "type ");
        let algo = crate::formats::util::val::name_or(
            COMPRESSION,
            main.uint(8).unwrap_or(0),
            "algorithm ",
        );
        let enc = if main.uint(10).unwrap_or(1) == 2 {
            ", Blowfish-encrypted"
        } else {
            ""
        };
        cx.annotate(format!(
            "FSArchiver archive ({kind}), {} by fsarchiver {}, {algo}{enc}",
            main.string(1).unwrap_or_default(),
            main.string(2).unwrap_or_default()
        ));
    }
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < region.len {
        let at = (pos, index);
        cx.progress_in(region, pos);
        let header = match read_header(&cx, region, pos).await {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                let span = region.tail(pos);
                cx.mark(move || at);
                cx.push(
                    Node::new("Unparsed data")
                        .span(span)
                        .summary(size(span.len))
                        .diag(e),
                )
                .await;
                break;
            }
        };
        let (node, end) = match &header.magic {
            b"BlKh" => {
                let block = match block_at(region, header.clone()) {
                    Ok(b) => b,
                    Err(e) => {
                        cx.mark(move || at);
                        cx.push(header_node(header.clone()).diag(e)).await;
                        break;
                    }
                };
                let end = block.data.end().saturating_sub(region.offset);
                let node = Node::new("Block")
                    .span(region.sub(pos, end.saturating_sub(pos)))
                    .summary(format!("{} (shared by small files)", block.summary()))
                    .lazy(block_node, (input, block));
                (node, end)
            }
            b"ObJt" if header.uint(3) == Some(8) => file_node(&cx, input, header).await?,
            _ => {
                let end = header.span.end().saturating_sub(region.offset);
                (header_node(header), end)
            }
        };
        cx.mark(move || at);
        cx.push(node).await;
        index = index.saturating_add(1);
        pos = end.max(pos.saturating_add(1));
    }
    cx.progress_in(region, region.len);
    Ok(())
}

/// The node of a header (not a block), named for what it is.
fn header_node(h: Header) -> Node {
    let mut name = h.name().to_string();
    let mut summary = String::new();
    match &h.magic {
        b"ObJt" => {
            name = h.string(2).unwrap_or_else(|| "Object".into());
            summary = object_summary(&h);
        }
        b"FsA0" => summary = format!("volume {}", h.uint(0).unwrap_or(0)),
        b"FsAE" => {
            summary = format!(
                "volume {}{}",
                h.uint(0).unwrap_or(0),
                if h.uint(2) == Some(1) {
                    ", the last"
                } else {
                    ""
                }
            );
        }
        b"FsIn" => {
            summary = format!(
                "{}{}",
                h.string(1).unwrap_or_default(),
                h.string(5)
                    .filter(|l| !l.is_empty())
                    .map(|l| format!(", label {l:?}"))
                    .unwrap_or_default()
            );
        }
        b"ArCh" => {
            summary = format!(
                "{}, {}",
                crate::formats::util::val::name_or(ARCHIVE_TYPES, h.uint(6).unwrap_or(0), "type "),
                crate::formats::util::val::name_or(
                    COMPRESSION,
                    h.uint(8).unwrap_or(0),
                    "algorithm "
                )
            );
        }
        _ => {}
    }
    let mut node = Node::new(name).span(h.span);
    if !summary.is_empty() {
        node = node.summary(summary);
    }
    if h.computed != h.checksum {
        node = node.diag(Diagnostic::warning(format!(
            "header checksum {:#010x}, computed {:#010x}",
            h.checksum, h.computed
        )));
    }
    node.lazy(fields, h)
}

fn object_summary(h: &Header) -> String {
    let kind = crate::formats::util::val::name_or(OBJECT_TYPES, h.uint(3).unwrap_or(0), "type ");
    let mut s = kind;
    if let Some(mode) = h.uint(7) {
        s.push_str(", ");
        s.push_str(&unix_mode(mode));
    }
    if matches!(h.uint(3), Some(8 | 9)) {
        s.push_str(", ");
        s.push_str(&size(h.uint(8).unwrap_or(0)));
    }
    if let Some(target) = h.string(4) {
        s.push_str(" → ");
        s.push_str(&target);
    }
    s
}

/// The fields of a header: the fixed part, the dictionary, the checksum.
async fn fields(cx: Cx, h: Header) -> Result<()> {
    let s = h.span;
    cx.emit(
        Node::new("Magic")
            .span(s.sub(0, 4))
            .value(text(crate::text::latin1(&h.magic))),
    );
    cx.emit(
        Node::new("Archive id")
            .span(s.sub(4, 4))
            .value(hex(h.archive, 32)),
    );
    let mut fs = Node::new("Filesystem index")
        .span(s.sub(8, 2))
        .value(uint(h.fs, 16));
    if h.fs == 0xffff {
        fs = fs.summary("none");
    }
    cx.emit(fs);
    let dico = s.sub(10, 4);
    cx.emit(
        Node::new("Dictionary size")
            .span(dico)
            .value(uint(s.len.saturating_sub(FIXED).saturating_sub(4), 32)),
    );
    for item in &h.items {
        cx.push(item_node(&h.magic, item)).await;
    }
    let ck = s.sub(s.len.saturating_sub(4), 4);
    let mut node = Node::new("Checksum")
        .span(ck)
        .value(hex(h.checksum, 32))
        .desc("Fletcher-32 of the dictionary");
    if h.checksum != h.computed {
        node = node.diag(Diagnostic::warning(format!(
            "computed {:#010x}",
            h.computed
        )));
    }
    cx.push(node).await;
    Ok(())
}

fn item_node(magic: &[u8; 4], item: &Item) -> Node {
    let known = (item.section == 0)
        .then(|| key_name(magic, item.key))
        .flatten();
    let name = match (known, item.section) {
        (Some((n, _)), _) => n.to_string(),
        (None, 0) => format!("Key {}", item.key),
        (None, 1) => format!("Extended attribute item {}", item.key),
        (None, 2) => format!("Windows attribute item {}", item.key),
        (None, s) => format!("Section {s} key {}", item.key),
    };
    let show = known.map_or(Show::Plain, |(_, s)| s);
    let bits = u8::try_from(item.data.len().saturating_mul(8)).unwrap_or(64);
    let mut node = Node::new(name).span(item.span);
    node = match (item.kind, item.uint()) {
        (_, Some(v)) => match show {
            Show::Hex => node.value(hex(v, bits)),
            Show::Time => node.value(Value::Timestamp {
                unix_seconds: i64::try_from(v).unwrap_or(i64::MAX),
            }),
            Show::Mode => node.value(text(format!("{v:o}"))).summary(unix_mode(v)),
            Show::Size => node.value(uint(v, bits)).summary(size(v)),
            Show::Enum(t) => node.value(enumv(v, bits, t)),
            Show::Plain => node.value(uint(v, bits)),
        },
        (6, None) => node.value(text(item.string())),
        _ => node.value(Value::Bytes(item.data.clone())),
    };
    node
}

/// A block's fields, the check of its data and its decoded content.
async fn block_node(cx: Cx, (input, block): (Input, Block)) -> Result<()> {
    cx.emit(header_node(block.header.clone()).renamed("Block header"));
    let mut data = Node::new("Data").span(block.data).summary(block.summary());
    if let Some(stored) = block.header.uint(7) {
        let mut f = Fletcher::new();
        let mut pos = 0u64;
        while pos < block.data.len {
            let n = CHUNK.min(block.data.len.saturating_sub(pos));
            let raw = cx.read(block.data.sub(pos, n)).await?;
            f.update(&raw);
            cx.charge(n / 1024).await;
            pos = pos.saturating_add(n);
        }
        let computed = f.value();
        if u64::from(computed) != stored {
            data = data.diag(Diagnostic::warning(format!(
                "block checksum {stored:#010x}, computed {computed:#010x}"
            )));
        }
    }
    cx.emit(data);
    match block.codec() {
        Ok(codec) => cx.emit(content(
            "Content",
            input,
            block.data,
            codec,
            Some(block.decoded()),
        )),
        Err(e) => cx.emit(Node::new("Content").span(block.data).diag(e)),
    }
    Ok(())
}

/// What a file stored in its own blocks consists of.
#[derive(Clone, Debug)]
struct File {
    input: Input,
    object: Header,
    blocks: Arc<Vec<Block>>,
    footer: Option<Header>,
}

/// A regular file stored in blocks of its own: its object header, then
/// its blocks and footer, read here to group them.
async fn file_node(cx: &Cx, input: Input, object: Header) -> Result<(Node, u64)> {
    let region = input.span;
    let mut pos = object.span.end().saturating_sub(region.offset);
    let mut blocks = Vec::new();
    let mut footer = None;
    let mut problem = None;
    loop {
        let h = match read_header(cx, region, pos).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                problem = Some(Diagnostic::malformed(
                    "the archive ends before the file's footer",
                ));
                break;
            }
            Err(e) => {
                problem = Some(e);
                break;
            }
        };
        match &h.magic {
            b"BlKh" => match block_at(region, h) {
                Ok(b) => {
                    pos = b.data.end().saturating_sub(region.offset);
                    blocks.push(b);
                }
                Err(e) => {
                    problem = Some(e);
                    break;
                }
            },
            b"FiLf" => {
                pos = h.span.end().saturating_sub(region.offset);
                footer = Some(h);
                break;
            }
            _ => {
                problem = Some(Diagnostic::malformed(format!(
                    "{} where the file's blocks or footer should be",
                    h.name()
                )));
                break;
            }
        }
    }
    let start = object.span.offset.saturating_sub(region.offset);
    let span = region.sub(start, pos.saturating_sub(start));
    let decoded: u64 = blocks
        .iter()
        .map(Block::decoded)
        .fold(0, u64::saturating_add);
    let mut node = Node::new(object.string(2).unwrap_or_else(|| "Object".into()))
        .span(span)
        .summary(format!(
            "{}, {}",
            object_summary(&object),
            plural(blocks.len(), "block")
        ));
    if decoded != object.uint(8).unwrap_or(0) {
        node = node.diag(Diagnostic::warning(format!(
            "the blocks hold {decoded} bytes; the object says {}",
            object.uint(8).unwrap_or(0)
        )));
    }
    if let Some(p) = problem {
        node = node.diag(p);
    }
    let file = File {
        input,
        object,
        blocks: Arc::new(blocks),
        footer,
    };
    Ok((node.lazy(file_children, file), pos))
}

async fn file_children(cx: Cx, file: File) -> Result<()> {
    cx.emit(header_node(file.object.clone()).renamed("Object header"));
    for (i, b) in file.blocks.iter().enumerate() {
        let h = b.header.span;
        let span = Span::new(h.source, h.offset, b.data.end().saturating_sub(h.offset));
        cx.push(
            Node::new(format!("Block {i}"))
                .span(span)
                .summary(b.summary())
                .lazy(block_node, (file.input, b.clone())),
        )
        .await;
    }
    if let Some(f) = &file.footer {
        cx.push(header_node(f.clone())).await;
    }
    let size = file.object.uint(8).unwrap_or(0);
    let node = match file.blocks.as_slice() {
        [one] => match one.codec() {
            Ok(codec) => content("Content", file.input, one.data, codec, Some(one.decoded())),
            Err(e) => Node::new("Content").diag(e),
        },
        _ => Node::new("Content")
            .summary(crate::formats::util::fmt::size(size))
            .lazy(joined, file.clone()),
    };
    cx.push(node).await;
    Ok(())
}

/// A file of several blocks: each decoded on demand, joined as pieces.
async fn joined(cx: Cx, file: File) -> Result<()> {
    let mut pieces = Vec::with_capacity(file.blocks.len());
    for (i, b) in file.blocks.iter().enumerate() {
        if i % 256 == 0 {
            cx.checkpoint().await;
        }
        let codec = b.codec().map_err(|e| e.at(b.data))?;
        pieces.push(cx.decode_lazy(b.data, &codec, b.decoded())?);
    }
    let span = cx
        .add_pieces_stepped(
            Origin {
                parent: file.object.span,
                transform: "fsarchiver-file",
            },
            &pieces,
        )
        .await?;
    dissect_or_data(cx, file.input.nested(span)).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn fletcher(data: &[u8]) -> u32 {
        let mut f = Fletcher::new();
        f.update(data);
        f.value()
    }

    /// Values from fsarchiver 0.8.8 archives: an empty dictionary (the
    /// `DaEn` header's) and a volume header's.
    #[test]
    fn fletcher_matches_fsarchiver() {
        assert_eq!(fletcher(&[0, 0]), 0xffff_ffff);
        let mut dico = vec![4, 0];
        dico.extend_from_slice(&[3, 0, 0, 0, 4, 0, 0, 0, 0, 0]);
        dico.extend_from_slice(&[3, 0, 1, 0, 4, 0, 0x80, 0x00, 0x92, 0x65]);
        dico.extend_from_slice(&[6, 0, 2, 0, 11, 0]);
        dico.extend_from_slice(b"FsArCh_002\0");
        dico.extend_from_slice(&[6, 0, 3, 0, 6, 0]);
        dico.extend_from_slice(b"0.8.8\0");
        assert_eq!(fletcher(&dico), 0x7137_05b0);
        // Updates split anywhere give the same sum.
        let mut f = Fletcher::new();
        f.update(&dico[..7]);
        f.update(&dico[7..]);
        assert_eq!(f.value(), 0x7137_05b0);
    }

    #[test]
    fn probe_wants_a_dictionary() {
        let head = |data: &[u8]| {
            probe(&Head {
                data,
                tail: data,
                len: data.len() as u64,
                len_known: true,
            })
        };
        let mut good = b"FsA0\x80\x00\x92\x65\xff\xff\x33\x00\x00\x00\x04\x00".to_vec();
        good.extend_from_slice(&[3, 0, 0, 0, 4, 0, 0, 0, 0, 0]);
        assert!(head(&good));
        assert!(!head(b"FsA0 is how this text starts, not an archive"));
        let mut huge = good.clone();
        huge[10..14].copy_from_slice(&0x0100_0000u32.to_le_bytes());
        assert!(!head(&huge));
        let mut kind = good.clone();
        kind[16] = 9;
        assert!(!head(&kind));
    }
}
