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
//! first, each with its offset in the shared block that follows them; each
//! one's content is its slice of that block, decoded on demand (the
//! listing looks ahead once per run of objects for the block). Larger
//! files are an object, their own blocks and a footer; the listing groups
//! those, and their content is the blocks decoded on demand, one piece per
//! block. Blocks decode with the existing codecs: LZO1X, zlib ("gzip"),
//! bzip2, xz ("lzma"), raw LZ4 blocks and zstd; Blowfish encryption is not
//! supported (its blocks are listed, not decoded), nor is the MD5 of file
//! contents checked.
//!
//! The listing groups the data by section: one node per filesystem
//! (its `FsIn`, then `FsYs` … `DaEn`), or one for the directories of a
//! `savedir` archive (`DiRs`, then the objects … `DaEn`), between the
//! volume and archive headers and the volume footer (found at the end).
//! Nothing records where a section starts, so the top level does not walk
//! the data: a section after the first finds its start by walking the
//! headers of the ones before it (skipping block data), once. Extended
//! attributes (section 1 items, a name under an even key and its value
//! under the next) are shown in pairs, POSIX ACLs as `getfacl` text.
//!
//! A split archive (`-s`) is several files, `.fsa`, `.f01`, ..., each
//! starting with a volume header and ending with a volume footer that says
//! whether it is the last. A large file's blocks may go on into the next
//! volume: its node says so, and the blocks and footer at the start of the
//! next volume are labelled as the continuation. Volumes are dissected one
//! at a time; nothing joins them. A volume after the first (which has no
//! archive header saying what its sections are) is walked to list its
//! sections.
//!
//! Written from archives made by fsarchiver 0.8.8 (`savedir` with every
//! compression algorithm and with encryption, and `savefs` of an ext2
//! filesystem, a split archive, `savefs` of an ext4 and an ext2
//! filesystem whose descriptions were checked against `dumpe2fs`, and
//! `savefs` of an ext4 holding extended attributes, an ACL, a hard link,
//! devices, a FIFO and a socket;
//! fixtures in `tests/fixtures/external/fsarchiver/`): the
//! header magics, the dictionary encoding and the Fletcher-32 checksums
//! were worked out from those archives, the meaning of the keys from what
//! they hold there and from memory of fsarchiver's sources (none were read
//! or copied). Keys whose meaning was not established are shown by number.

use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::disk::ext::{COMPAT, INCOMPAT, RO_COMPAT};
use crate::formats::util::arcutil::unix_mode;
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{enumv, flagsv, hex, text, uint};
use crate::formats::{Codec, Format, Head, Input, Probe, content, dissect_or_data};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value};

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

/// What wrote the archive: `savefs` (filesystems) or `savedir` (directories).
const ARCHIVE_TYPES: EnumTable = &[(1, "savefs"), (2, "savedir")];
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
    /// fsarchiver's packed version: four 16-bit parts, major first.
    Version,
    /// A `dev_t` as glibc encodes it.
    Device,
    Enum(EnumTable),
    Flags(FlagTable),
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
        (b"ArCh", 14) => ("Minimum fsarchiver version", Version),
        (b"ArCh", 15) => ("Has directories info", Plain),
        // Content bytes plus 16 KiB per object (checked on the savedir
        // fixtures): what fsarchiver shows progress against.
        (b"DiRs", 1) => ("Total cost", Plain),
        (b"FsIn", 1) => ("Filesystem", Plain),
        (b"FsIn", 2) => ("Mount point", Plain),
        (b"FsIn", 3) => ("Total bytes", Size),
        (b"FsIn", 4) => ("Used bytes", Size),
        (b"FsIn", 5) => ("Label", Plain),
        (b"FsIn", 6) => ("UUID", Plain),
        (b"FsIn", 7) => ("ext inode size", Plain),
        (b"FsIn", 9) => ("Default mount options", Plain),
        (b"FsIn", 10) => ("ext revision", Plain),
        (b"FsIn", 11) => ("ext block size", Plain),
        (b"FsIn", 12) => ("ext compatible features", Flags(COMPAT)),
        (b"FsIn", 13) => ("ext incompatible features", Flags(INCOMPAT)),
        (b"FsIn", 14) => ("ext read-only compatible features", Flags(RO_COMPAT)),
        (b"FsIn", 25) => ("Minimum fsarchiver version", Version),
        (b"FsIn", 27) => ("Device", Plain),
        (b"ObJt", 1) => ("Object id", Plain),
        (b"ObJt", 2) => ("Path", Plain),
        (b"ObJt", 3) => ("Object type", Enum(OBJECT_TYPES)),
        (b"ObJt", 4) => ("Link target", Plain),
        (b"ObJt", 5) => ("Hard link target", Plain),
        (b"ObJt", 6) => ("Device number", Device),
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

/// Small-file objects looked ahead at most for their shared block (fsarchiver
/// packs far fewer into one); a longer run is looked at again from where
/// this lookahead stopped.
const MAX_GROUP: u64 = 1 << 16;

/// The shared block of a run of small files, found by looking ahead from
/// the first of them.
#[derive(Clone, Debug)]
struct Lookahead {
    /// Where the lookahead stopped (the block's header, or what stopped
    /// it): objects before this share its answer.
    until: u64,
    block: std::result::Result<Arc<Block>, Diagnostic>,
}

/// Looks for the block shared by the small files whose objects start at
/// `pos`: fsarchiver writes a run of their objects, then the block.
async fn find_shared(cx: &Cx, region: Span, mut pos: u64) -> Lookahead {
    for _ in 0..MAX_GROUP {
        let h = match read_header(cx, region, pos).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                return Lookahead {
                    until: pos,
                    block: Err(Diagnostic::malformed(
                        "the archive ends before the shared block",
                    )),
                };
            }
            Err(e) => {
                return Lookahead {
                    until: pos,
                    block: Err(e),
                };
            }
        };
        let problem = match &h.magic {
            b"BlKh" => {
                return Lookahead {
                    until: pos,
                    block: block_at(region, h).map(Arc::new),
                };
            }
            b"ObJt" if h.uint(3) == Some(9) => {
                pos = h.span.end().saturating_sub(region.offset);
                continue;
            }
            b"FsAE" if h.uint(2) != Some(1) => {
                Diagnostic::note("the shared block is in the next volume of the archive")
            }
            _ => Diagnostic::malformed(format!("{} where the shared block should be", h.name())),
        };
        return Lookahead {
            until: pos,
            block: Err(problem),
        };
    }
    Lookahead {
        until: pos,
        block: Err(Diagnostic::unsupported(format!(
            "more than {MAX_GROUP} small files before their shared block"
        ))),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let region = input.span;
    // The volume and archive headers, for the summary.
    if let Some(volume) = read_header(&cx, region, 0).await?
        && volume.magic == *b"FsA0"
    {
        match read_header(&cx, region, volume.span.len).await? {
            Some(main) if main.magic == *b"ArCh" => {
                let kind = crate::formats::util::val::name_or(
                    ARCHIVE_TYPES,
                    main.uint(6).unwrap_or(0),
                    "type ",
                );
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
                    "FSArchiver archive: {kind}, {} by fsarchiver {}, {algo}{enc}",
                    main.string(1).unwrap_or_default(),
                    main.string(2).unwrap_or_default()
                ));
            }
            _ => cx.annotate(format!(
                "FSArchiver archive, volume {} of a split archive (id {:#010x})",
                volume.uint(0).unwrap_or(0),
                volume.archive
            )),
        }
    }
    // The headers before the data: volume and archive headers (listed
    // here), filesystem and directories descriptions (listed first in the
    // sections they describe).
    let mut pos = 0u64;
    let mut infos = Vec::new();
    let mut dirs = None;
    let mut continued = false;
    loop {
        let header = match read_header(&cx, region, pos).await {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                cx.push(unparsed(region.tail(pos), e)).await;
                return Ok(());
            }
        };
        let end = header.span.end().saturating_sub(region.offset);
        match &header.magic {
            b"FsA0" => {
                continued = header.uint(0).is_some_and(|v| v > 0);
                cx.push(header_node(header)).await;
            }
            b"ArCh" => cx.push(header_node(header)).await,
            b"FsIn" => infos.push(header),
            b"DiRs" => dirs = Some(header),
            _ => break,
        }
        pos = end;
    }
    let footer = if continued || (infos.is_empty() && dirs.is_none()) {
        None
    } else {
        find_footer(&cx, region, pos).await
    };
    let Some(footer) = footer else {
        // A volume that continues the previous one, or one that does not
        // end with its footer: its sections are found by walking it.
        for info in infos.into_iter().chain(dirs) {
            cx.push(header_node(info)).await;
        }
        return walk_sections(&cx, input, pos, continued).await;
    };
    let archive = Arc::new(Archive {
        input,
        first: pos,
        end: footer.span.offset.saturating_sub(region.offset),
    });
    if infos.is_empty() {
        cx.push(Node::new("Directories").lazy(section, Section::planned(&archive, 0, dirs)))
            .await;
    } else {
        for (i, info) in infos.into_iter().enumerate() {
            let i = crate::bytes::to_u64(i);
            cx.push(
                Node::new(format!("Filesystem {i}"))
                    .summary(fs_summary(&info))
                    .lazy(section, Section::planned(&archive, i, Some(info))),
            )
            .await;
        }
    }
    cx.push(header_node(footer)).await;
    Ok(())
}

/// A filesystem's description, short.
fn fs_summary(info: &Header) -> String {
    let mut s = info.string(1).unwrap_or_else(|| "filesystem".into());
    if let Some(label) = info.string(5).filter(|l| !l.is_empty() && l != "<none>") {
        s.push_str(&format!(", label {label:?}"));
    }
    if let (Some(used), Some(total)) = (info.uint(4), info.uint(3)) {
        s.push_str(&format!(", {} used of {}", size(used), size(total)));
    }
    s
}

fn unparsed(span: Span, e: Diagnostic) -> Node {
    Node::new("Unparsed data")
        .span(span)
        .summary(size(span.len))
        .diag(e)
}

/// The volume footer, which ends a well-formed volume: looked for in the
/// last bytes (its dictionary's size varies), and taken only if it ends
/// exactly at the end and its checksum holds. `None` if it is not there,
/// or if reading the end would decode far into content.
async fn find_footer(cx: &Cx, region: Span, from: u64) -> Option<Header> {
    const LOOK: u64 = 512;
    let n = LOOK.min(region.len.saturating_sub(from));
    let start = region.len.saturating_sub(n);
    let tail = region.sub(start, n);
    if !cx.read_is_cheap(tail) {
        return None;
    }
    let raw = cx.read(tail).await.ok()?;
    let hits: Vec<u64> = raw
        .windows(4)
        .enumerate()
        .rev()
        .filter(|(_, w)| *w == b"FsAE")
        .map(|(i, _)| start.saturating_add(crate::bytes::to_u64(i)))
        .collect();
    for at in hits {
        if let Ok(Some(h)) = read_header(cx, region, at).await
            && h.span.end().saturating_sub(region.offset) == region.len
            && h.computed == h.checksum
        {
            return Some(h);
        }
    }
    None
}

/// What the sections of a volume share.
#[derive(Debug)]
struct Archive {
    input: Input,
    /// Where the first section starts (relative to the input).
    first: u64,
    /// Where the sections end (the volume footer).
    end: u64,
}

/// One filesystem's data (`FsYs` … `DaEn`), or the directories' (a
/// `savedir` archive's objects … `DaEn`).
#[derive(Clone, Debug)]
struct Section {
    archive: Arc<Archive>,
    /// Which section of the volume: its start is found by walking the
    /// ones before it, once.
    ordinal: u64,
    /// The filesystem or directories description, listed first.
    info: Option<Header>,
    /// Whether it starts with the blocks and footer of a file from the
    /// previous volume.
    continued: bool,
}

impl Section {
    fn planned(archive: &Arc<Archive>, ordinal: u64, info: Option<Header>) -> Self {
        Section {
            archive: archive.clone(),
            ordinal,
            info,
            continued: false,
        }
    }
}

/// Where section `ordinal` starts: the end of the one before it, walked
/// once and cached.
async fn section_start(cx: &Cx, archive: &Archive, ordinal: u64) -> u64 {
    const KIND: &str = "fsarchiver-section-end";
    let region = archive.input.span;
    let mut start = archive.first;
    for _ in 0..ordinal {
        let key = region.sub(start, 0);
        start = match cx.cached::<u64>(key, KIND) {
            Some(end) => *end,
            None => {
                let end = section_end(cx, region, start).await;
                cx.cache(key, KIND, Arc::new(end));
                end
            }
        };
    }
    start
}

/// Walks the headers of the section starting at `start` (skipping block
/// data) to where it ends: after its `DaEn`, before a volume footer or the
/// next filesystem's start, or where the headers stop making sense.
async fn section_end(cx: &Cx, region: Span, start: u64) -> u64 {
    let mut pos = start;
    loop {
        cx.progress_in(region, pos);
        let h = match read_header(cx, region, pos).await {
            Ok(Some(h)) => h,
            Ok(None) | Err(_) => return pos,
        };
        let end = h.span.end().saturating_sub(region.offset);
        match &h.magic {
            b"FsAE" => return pos,
            b"FsYs" if pos != start => return pos,
            b"DaEn" => return end,
            b"BlKh" => match block_at(region, h) {
                Ok(b) => pos = b.data.end().saturating_sub(region.offset),
                Err(_) => return pos,
            },
            _ => pos = end,
        }
    }
}

/// A volume whose sections are not known from its first headers (one
/// continuing the previous volume): lists each section, found by walking
/// it, and the headers between them.
async fn walk_sections(cx: &Cx, input: Input, mut pos: u64, mut continued: bool) -> Result<()> {
    let region = input.span;
    while pos < region.len {
        let header = match read_header(cx, region, pos).await {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                cx.push(unparsed(region.tail(pos), e)).await;
                break;
            }
        };
        let end = header.span.end().saturating_sub(region.offset);
        if matches!(
            &header.magic,
            b"FsA0" | b"FsAE" | b"ArCh" | b"FsIn" | b"DiRs"
        ) {
            cx.push(header_node(header)).await;
            pos = end;
            continue;
        }
        let end = section_end(cx, region, pos).await.max(end);
        let (name, summary) = match (&header.magic, header.fs) {
            (b"FsYs", fs) => (format!("Filesystem {fs}"), None),
            (_, 0xffff) => ("Data".to_string(), None),
            (_, fs) if continued => (
                "Continued data".to_string(),
                Some(format!("filesystem index {fs}, from the previous volume")),
            ),
            (_, fs) => ("Data".to_string(), Some(format!("filesystem index {fs}"))),
        };
        let mut node = Node::new(name).span(region.sub(pos, end.saturating_sub(pos)));
        if let Some(summary) = summary {
            node = node.summary(summary);
        }
        let archive = Arc::new(Archive {
            input,
            first: pos,
            end,
        });
        cx.push(node.lazy(
            section,
            Section {
                archive,
                ordinal: 0,
                info: None,
                continued,
            },
        ))
        .await;
        continued = false;
        pos = end;
    }
    Ok(())
}

/// A section's headers: its description, then everything from its start
/// to its end (paged, with resume marks).
async fn section(cx: Cx, s: Section) -> Result<()> {
    let input = s.archive.input;
    let region = input.span;
    let resumed = cx.resume::<(u64, u64, bool)>();
    let (mut pos, mut index, mut continued) = match resumed {
        Some(at) => at,
        None => {
            let start = section_start(&cx, &s.archive, s.ordinal).await;
            if let Some(info) = &s.info {
                cx.push(header_node(info.clone())).await;
            }
            (start, 0, s.continued)
        }
    };
    let mut shared: Option<Lookahead> = None;
    let end = s.archive.end.min(region.len);
    while pos < end {
        let at = (pos, index, continued);
        cx.progress_in(region, pos);
        let header = match read_header(&cx, region, pos).await {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                cx.mark(move || at);
                cx.push(unparsed(region.sub(pos, end.saturating_sub(pos)), e))
                    .await;
                break;
            }
        };
        match &header.magic {
            b"FsAE" => break,
            b"FsYs" if index > 0 => break,
            b"BlKh" | b"FiLf" => {}
            _ => continued = false,
        }
        let last = header.magic == *b"DaEn";
        let (node, next) = match &header.magic {
            b"BlKh" => {
                let block = match block_at(region, header.clone()) {
                    Ok(b) => b,
                    Err(e) => {
                        cx.mark(move || at);
                        cx.push(header_node(header.clone()).diag(e)).await;
                        break;
                    }
                };
                let next = block.data.end().saturating_sub(region.offset);
                let whose = if continued {
                    "of a file continued from the previous volume"
                } else {
                    "shared by small files"
                };
                let node = Node::new("Block")
                    .span(region.sub(pos, next.saturating_sub(pos)))
                    .summary(format!("{} ({whose})", block.summary()))
                    .lazy(block_node, (input, block));
                (node, next)
            }
            b"FiLf" if continued => {
                let next = header.span.end().saturating_sub(region.offset);
                let node =
                    header_node(header).summary("of a file continued from the previous volume");
                (node, next)
            }
            b"ObJt" if header.uint(3) == Some(8) => file_node(&cx, input, header).await?,
            b"ObJt" if header.uint(3) == Some(9) => {
                let look = match shared.take() {
                    Some(l) if pos < l.until => l,
                    _ => find_shared(&cx, region, pos).await,
                };
                let next = header.span.end().saturating_sub(region.offset);
                let node = small_file_node(input, header, look.block.clone());
                shared = Some(look);
                (node, next)
            }
            _ => {
                let next = header.span.end().saturating_sub(region.offset);
                (header_node(header), next)
            }
        };
        cx.mark(move || at);
        cx.push(node).await;
        index = index.saturating_add(1);
        pos = next.max(pos.saturating_add(1));
        if last {
            break;
        }
    }
    cx.progress_in(region, end);
    Ok(())
}

/// The node of a header (not a block), named for what it is.
fn header_node(h: Header) -> Node {
    header_line(&h).lazy(fields, h)
}

/// A header's node with no children yet.
fn header_line(h: &Header) -> Node {
    let mut name = h.name().to_string();
    let mut summary = String::new();
    match &h.magic {
        b"ObJt" => {
            name = h.string(2).unwrap_or_else(|| "Object".into());
            summary = object_summary(h);
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
    node
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
    if matches!(h.uint(3), Some(4 | 5))
        && let Some(dev) = h.uint(6)
    {
        let (major, minor) = dev_parts(dev);
        s.push_str(&format!(", {major}:{minor}"));
    }
    if let Some(target) = h.string(4).or_else(|| h.string(5)) {
        s.push_str(" → ");
        s.push_str(&target);
    }
    s
}

/// Major and minor numbers of a `dev_t` in glibc's encoding (12 + 20
/// bits, split around the old 8 + 8; checked on the fixtures' 1:3 and 7:0).
fn dev_parts(dev: u64) -> (u64, u64) {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major, minor)
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
    let mut items = h.items.iter().peekable();
    while let Some(item) = items.next() {
        // An extended attribute is two items of section 1: its name under
        // an even key, its value under the next.
        let value = items.next_if(|v| {
            v.section == 1
                && item.section == 1
                && item.kind == 6
                && item.key % 2 == 0
                && Some(v.key) == item.key.checked_add(1)
        });
        let node = match value {
            Some(v) => xattr_node(item, v),
            None => item_node(&h.magic, item),
        };
        cx.push(node).await;
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
            Show::Time => node.value(Value::utc(i64::try_from(v).unwrap_or(i64::MAX))),
            Show::Mode => node
                .value(crate::formats::util::val::oct(v, 64))
                .summary(unix_mode(v)),
            Show::Size => node.value(uint(v, bits)).summary(size(v)),
            Show::Enum(t) => node.value(enumv(v, bits, t)),
            Show::Flags(t) => node.value(flagsv(v, bits, t)),
            Show::Version => node.value(hex(v, bits)).summary(format!(
                "{}.{}.{}.{}",
                v >> 48,
                (v >> 32) & 0xffff,
                (v >> 16) & 0xffff,
                v & 0xffff
            )),
            Show::Device => {
                let (major, minor) = dev_parts(v);
                node.value(hex(v, bits)).summary(format!("{major}:{minor}"))
            }
            Show::Plain => node.value(uint(v, bits)),
        },
        (6, None) => node.value(text(item.string())),
        _ => node.value(Value::Bytes(item.data.clone())),
    };
    node
}

/// An extended attribute from its name and value items.
fn xattr_node(name: &Item, value: &Item) -> Node {
    let n = name.string();
    let span = Span::new(
        name.span.source,
        name.span.offset,
        value.span.end().saturating_sub(name.span.offset),
    );
    let mut node = Node::new(n.clone()).span(span);
    let data = value.data.strip_suffix(&[0]).unwrap_or(&value.data);
    if crate::formats::disk::acl::is_acl_name(n.as_bytes())
        && let Some(acl) = crate::formats::disk::acl::xattr_v2(&value.data)
    {
        node = node
            .value(Value::Bytes(value.data.clone()))
            .summary(format!("POSIX ACL: {acl}"));
    } else if let Ok(t) = std::str::from_utf8(data)
        && !t.is_empty()
        && crate::text::looks_like_text(data)
    {
        node = node.value(text(t));
    } else {
        node = node.value(Value::Bytes(value.data.clone()));
    }
    node.desc(format!(
        "Extended attribute (items {} and {})",
        name.key, value.key
    ))
}

/// A small file: what its object says, and a slice of its shared block.
#[derive(Clone, Debug)]
struct SmallFile {
    input: Input,
    object: Header,
    block: std::result::Result<Arc<Block>, Diagnostic>,
}

fn small_file_node(
    input: Input,
    object: Header,
    block: std::result::Result<Arc<Block>, Diagnostic>,
) -> Node {
    header_line(&object).lazy(
        small_file,
        SmallFile {
            input,
            object,
            block,
        },
    )
}

/// A small file's fields, then its content: its size (key 8) in bytes
/// from its offset (key 15) in the shared block's decoded content.
async fn small_file(cx: Cx, file: SmallFile) -> Result<()> {
    fields(cx.clone(), file.object.clone()).await?;
    let len = file.object.uint(8).unwrap_or(0);
    let offset = file.object.uint(15).unwrap_or(0);
    let node = Node::new("Content").summary(size(len));
    let node = match &file.block {
        Err(e) => node.diag(e.clone()),
        Ok(b) if offset.checked_add(len).is_none_or(|end| end > b.decoded()) => {
            node.span(b.data).diag(Diagnostic::malformed(format!(
                "bytes {offset:#x}+{len:#x} of a shared block of {}",
                size(b.decoded())
            )))
        }
        Ok(b) => match b.codec() {
            Err(e) => node.span(b.data).diag(e),
            Ok(codec) => {
                let shown = if matches!(codec, Codec::Stored) {
                    b.data.sub(offset, len)
                } else {
                    b.data
                };
                node.span(shown)
                    .lazy(shared_content, (file.input, b.clone(), offset, len))
            }
        },
    };
    cx.push(node).await;
    Ok(())
}

/// A slice of a shared block, decoded on demand.
async fn shared_content(
    cx: Cx,
    (input, block, offset, len): (Input, Arc<Block>, u64, u64),
) -> Result<()> {
    let codec = block.codec().map_err(|e| e.at(block.data))?;
    let whole = cx.decode_lazy(block.data, &codec, block.decoded())?;
    let span = whole.sub_exact(offset, len)?;
    dissect_or_data(cx, input.nested(span)).await
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
    // The volume the file goes on into (split archives).
    let mut next_volume = None;
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
            b"FsAE" if h.uint(2) != Some(1) => {
                next_volume = Some(h.uint(0).unwrap_or(0).saturating_add(1));
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
    if let Some(next) = next_volume {
        node = node.diag(Diagnostic::note(format!(
            "continued in volume {next}: the blocks here hold {decoded} of {} bytes",
            object.uint(8).unwrap_or(0)
        )));
    } else if decoded != object.uint(8).unwrap_or(0) {
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
