//! xfsdump archives (`xfsdump -f file`), the XFS filesystem backup format.
//!
//! A dump written to a file is one media file: a 4 KiB global header
//! (magic `xFSdump0`, version, checksum, time, host id, dump id, host name,
//! session label) whose upper part nests the drive header, the media header
//! (media label and ids, indexes), the content header (mount point, device,
//! filesystem type and id) and the inode content header (dump level and
//! attributes, base dump, root inode, inode counts). Then the inode map
//! (hunks of 4 pages, each 511 segments of 64 inodes with 3 bits of state
//! per inode), the directories (a file header holding the inode's `bstat`,
//! then directory entries: inode, generation, name, ending with a null
//! entry), and the other inodes (a file header, then extent headers: data
//! followed by its bytes, holes, alignment padding, and a last one; a
//! symbolic link has one data extent holding its target). A regular file
//! is dumped in extent groups of up to 16 MiB of data, each a file header
//! (whose offset is where the group starts in the file) and its extents;
//! the listing shows the groups of one inode as one file. An inode with
//! extended attributes is followed by a second file header flagged so,
//! then attribute records ending with a null one. A file header flagged
//! as the end closes the dump. Everything is big-endian.
//!
//! Header checksums make the 32-bit words of the header, in the byte order
//! of the machine that wrote it, sum to zero (with its 16-bit fields and
//! strings laid out as that machine has them); both orders are accepted.
//!
//! The listing names directories and files by their paths, from the
//! directory entries (read once and cached); a file's content is its data
//! extents and holes as a piecewise source. A hard-linked inode is named
//! by its first entry, its summary listing the others; device numbers are
//! XFS's (major above 18 bits of minor); POSIX ACLs (`SGI_ACL_FILE`,
//! `SGI_ACL_DEFAULT`) are shown as `getfacl` text. Checksum mismatches are
//! warnings; directory entries are checked only when the dump attributes
//! say they carry checksums, extents when their own flag does.
//!
//! Written from xfsdump 3.2.0's headers (`common/global.h`, `drive.h`,
//! `media.h`, `content.h`, `content_inode.h`, `dump/inomap.h`; read for
//! facts only, no code copied) and checked against dumps written by
//! xfsdump 3.2.0 (fixtures in `tests/fixtures/external/xfsdump/`). Dumps
//! written to tape drives, in records with their own headers, and multiple
//! media files or streams are not handled.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, size, uuid_value};
use crate::formats::util::arcutil::unix_mode;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Format, Input, Probe, dissect_or_data};
use crate::node::Node;
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{Check, EnumTable, FlagTable, Value, flag};

pub static FORMAT: Format = Format {
    name: "xfsdump",
    title: "xfsdump archive",
    extensions: &["xfsdump"],
    mime: "application/x-xfsdump",
    probe: Probe::Magic(&[(0, b"xFSdump0")]),
    dissect: crate::expander!(dissect: Input),
};

const BE: Endian = Endian::Big;
const PAGE: u64 = 4096;
const HUNK: u64 = 4 * PAGE;
const SEGS_PER_HUNK: u64 = HUNK / 32 - 1;
const FILEHDR: u64 = 256;
const EXTENTHDR: u64 = 32;
const DIRENTHDR: u64 = 24;
const ATTRHDR: u64 = 16;
/// Path components followed at most when naming an inode.
const MAX_DEPTH: usize = 256;

const FH_NULL: u32 = 1;
const FH_END: u32 = 4;
const FH_EXTATTR: u32 = 8;
const EXT_LAST: u32 = 0;
const EXT_ALIGN: u32 = 1;
const EXT_DATA: u32 = 4;
const EXT_HOLE: u32 = 8;
const ATTR_NULL: u16 = 2;
/// Dump attribute: directory entries carry checksums.
const DIRENT_CHECKSUMS: u32 = 1 << 10;

const MEDIA_FILE_TYPES: EnumTable = &[(0, "data"), (1, "inventory"), (2, "index")];
const DUMP_ATTRS: FlagTable = &[
    flag(1 << 0, "SUBTREE"),
    flag(1 << 1, "INDEX"),
    flag(1 << 2, "INVENTORY"),
    flag(1 << 3, "INCREMENTAL"),
    flag(1 << 4, "RETRY"),
    flag(1 << 5, "RESUME"),
    flag(1 << 6, "INOMAP"),
    flag(1 << 7, "DIRDUMP"),
    flag(1 << 8, "FILEHDR_CHECKSUM"),
    flag(1 << 9, "EXTENTHDR_CHECKSUM"),
    flag(1 << 10, "DIRENTHDR_CHECKSUM"),
    flag(1 << 11, "DIRENTHDR_GEN"),
    flag(1 << 12, "EXTATTR"),
    flag(1 << 13, "EXTATTRHDR_CHECKSUM"),
    flag(1 << 14, "NOTSELFCONTAINED"),
];
const FILE_FLAGS: FlagTable = &[
    flag(1 << 0, "NULL"),
    flag(1 << 1, "CHECKSUM"),
    flag(1 << 2, "END"),
    flag(1 << 3, "EXTATTR"),
];
/// The extended flags of a `bstat` (FS_XFLAG_* of `linux/fs.h`).
const XFLAGS: FlagTable = &[
    flag(0x1, "REALTIME"),
    flag(0x2, "PREALLOC"),
    flag(0x8, "IMMUTABLE"),
    flag(0x10, "APPEND"),
    flag(0x20, "SYNC"),
    flag(0x40, "NOATIME"),
    flag(0x80, "NODUMP"),
    flag(0x100, "RTINHERIT"),
    flag(0x200, "PROJINHERIT"),
    flag(0x400, "NOSYMLINKS"),
    flag(0x800, "EXTSIZE"),
    flag(0x1000, "EXTSZINHERIT"),
    flag(0x2000, "NODEFRAG"),
    flag(0x4000, "FILESTREAM"),
    flag(0x8000, "DAX"),
    flag(0x10000, "COWEXTSIZE"),
    flag(0x8000_0000, "HASATTR"),
];
const EXTENT_TYPES: EnumTable = &[(0, "last"), (1, "align"), (4, "data"), (8, "hole")];
const ATTR_FLAGS: FlagTable = &[
    flag(1 << 0, "ROOT"),
    flag(1 << 1, "NULL"),
    flag(1 << 2, "OLD_CHECKSUM"),
    flag(1 << 3, "SECURE"),
    flag(1 << 4, "CHECKSUM"),
];
const INODE_STATES: &[&str] = &[
    "unused",
    "unchanged directories (not dumped)",
    "unchanged files (not dumped)",
    "changed directories",
    "changed files",
    "unchanged directories kept for the hierarchy",
    "reserved (state 6)",
    "reserved (state 7)",
];

record! {
    /// The global header's own fields.
    pub struct GlobalHeader {
        magic: ascii[8] "Magic",
        version: u32 "Version",
        checksum: u32 "Checksum" .checksum(XFSDUMP_SUM),
        time: u32 "Dump time" .timestamp(),
        _pad1: bytes[4] "Padding",
        host_id: u64 "Host id" .hex() .desc("From gethostid(3)"),
        dump_id: bytes[16] "Dump session id" .with(uuid_value),
        _pad2: bytes[0xd0] "Padding",
        host: ascii[256] "Host name",
        label: ascii[256] "Session label",
        _pad3: bytes[256] "Padding",
    }
}

record! {
    /// The drive header (in the global header's upper part).
    pub struct DriveHeader {
        drive_count: u32 "Drives",
        drive_index: u32 "Drive index",
        strategy: i32 "Drive strategy" .enumeration(DRIVE_STRATEGIES),
        _pad1: bytes[0x1f4] "Padding",
        _specific: bytes[0x200] "Strategy-specific",
    }
}

record! {
    /// The media header (in the drive header's upper part).
    pub struct MediaHeader {
        label: ascii[256] "Media label",
        prev_label: ascii[256] "Previous media label",
        _pad1: bytes[256] "Padding",
        media_id: bytes[16] "Media id" .with(uuid_value),
        prev_media_id: bytes[16] "Previous media id" .with(uuid_or_none),
        _pad2: bytes[16] "Padding",
        media_index: u32 "Media index",
        media_file_index: u32 "Media file index",
        dump_file_index: u32 "Dump file index",
        dump_media_file_index: u32 "Dump media file index",
        dump_media_index: u32 "Dump media index",
        strategy: i32 "Media strategy",
        _pad3: bytes[0x38] "Padding",
        _specific: bytes[0x80] "Strategy-specific",
    }
}

record! {
    /// The content header (in the media header's upper part).
    pub struct ContentHeader {
        mount_point: ascii[256] "Mount point",
        device: ascii[256] "Device",
        _pad1: bytes[256] "Padding",
        fs_type: ascii[16] "Filesystem type",
        fs_id: bytes[16] "Filesystem id" .with(uuid_value),
        _pad2: bytes[16] "Padding",
        _pad3: bytes[8] "Padding",
        strategy: i32 "Content strategy",
        _pad4: bytes[4] "Padding",
    }
}

record! {
    /// The inode content header (the content header's specific part).
    pub struct InodeHeader {
        media_file_type: i32 "Media file type" .enumeration(MEDIA_FILE_TYPES),
        attrs: u32 "Dump attributes" .hex() .flags(DUMP_ATTRS),
        level: i32 "Dump level",
        _pad1: bytes[4] "Padding",
        last_time: u32 "Base dump time" .with(time_or_unset),
        resume_time: u32 "Resumed dump time" .with(time_or_unset),
        root: u64 "Root inode",
        last_id: bytes[16] "Base dump id" .with(uuid_or_none),
        resume_id: bytes[16] "Resumed dump id" .with(uuid_or_none),
        start_ino: u64 "Start point: inode",
        start_offset: i64 "Start point: offset",
        start_flags: i32 "Start point: flags" .hex(),
        _start_pad: i32 "Start point: padding",
        end_ino: u64 "End point: inode",
        end_offset: i64 "End point: offset",
        end_flags: i32 "End point: flags" .hex(),
        _end_pad: i32 "End point: padding",
        hunks: u64 "Inode map hunks",
        segments: u64 "Inode map segments",
        dirs: u64 "Directories",
        nondirs: u64 "Other inodes",
        first_ino: u64 "First inode",
        last_ino: u64 "Last inode",
        data_size: u64 "Data size" .with(|&v, n| n.summary(size(v))),
        _pad2: bytes[0x18] "Padding",
    }
}

/// Drive strategies: 1 is what dumps to a file or a pipe write (checked
/// on the fixtures); the others drive tapes (from memory: 0 SCSI tape, 2
/// remote tape), whose records carry headers of their own.
const DRIVE_STRATEGIES: EnumTable = &[(1, "simple (file or pipe)")];
const DRIVE_SIMPLE: i32 = 1;

/// A time field: 0 means none.
fn time_or_unset(v: &u32, n: Node) -> Node {
    if *v == 0 {
        return n.not_set();
    }
    n.value(Value::utc(i64::from(*v)))
}

/// A UUID field: all zeros means none.
fn uuid_or_none(b: &Vec<u8>, n: Node) -> Node {
    let n = uuid_value(b, n);
    if b.iter().all(|&x| x == 0) {
        n.summary("none")
    } else {
        n
    }
}

/// Major and minor numbers of a device as XFS stores it (14 bits of
/// major above 18 of minor; checked on the fixtures' 1:3 and 7:0).
fn dev_parts(rdev: u32) -> (u32, u32) {
    (rdev >> 18, rdev & 0x3_ffff)
}

/// Offsets of the nested headers in the first page.
const DRIVE_AT: u64 = 0x400;
const MEDIA_AT: u64 = 0x800;
const CONTENT_AT: u64 = 0xc00;
const INODE_AT: u64 = 0xf40;

/// Integer fields (offset, width) of the structures whose checksums are
/// over the writer's layout; everything else is bytes.
const FILEHDR_INTS: &[(usize, usize)] = &[
    (0, 8),
    (8, 4),
    (12, 4),
    // bstat, at 16
    (16, 8),
    (24, 4),
    (28, 4),
    (32, 4),
    (36, 4),
    (40, 4),
    (44, 4),
    (48, 8),
    (56, 4),
    (60, 4),
    (64, 4),
    (68, 4),
    (72, 4),
    (76, 4),
    (80, 8),
    (88, 4),
    (92, 4),
    (96, 4),
    (100, 4),
    (104, 2),
    (106, 2),
    (108, 2),
    (120, 4),
    (124, 2),
];
const EXTENT_INTS: &[(usize, usize)] = &[(0, 8), (8, 8), (16, 4), (20, 4), (24, 4)];
const DIRENT_INTS: &[(usize, usize)] = &[(0, 8), (8, 4), (12, 4), (16, 2)];
const ATTR_INTS: &[(usize, usize)] = &[(0, 4), (4, 2), (6, 2), (8, 4), (12, 4)];

/// xfsdump's header checksums: the header's 32-bit words sum to zero.
const XFSDUMP_SUM: &str = "32-bit word sum";

/// A header checksum, by whether the header's words sum to zero (the
/// value they should have depends on the writer's byte order).
fn sum_check(stored: u32, ok: bool) -> Check {
    Check::new(XFSDUMP_SUM, stored).verified(ok)
}

/// Whether the words of `raw` sum to zero, as written (big-endian) or with
/// the integer fields `ints` laid out little-endian (the usual writer).
fn checksum_ok(raw: &[u8], ints: &[(usize, usize)]) -> bool {
    let sum = |b: &[u8], big: bool| {
        b.as_chunks::<4>().0.iter().fold(0u32, |acc, &w| {
            acc.wrapping_add(if big {
                u32::from_be_bytes(w)
            } else {
                u32::from_le_bytes(w)
            })
        })
    };
    if sum(raw, true) == 0 {
        return true;
    }
    let mut host = raw.to_vec();
    for &(at, width) in ints {
        if let Some(field) = host.get_mut(at..at.saturating_add(width)) {
            field.reverse();
        }
    }
    sum(&host, false) == 0
}

fn be_u64(raw: &[u8], at: usize) -> u64 {
    crate::bytes::u64_be(raw, at).unwrap_or(0)
}

fn be_u32(raw: &[u8], at: usize) -> u32 {
    crate::bytes::u32_be(raw, at).unwrap_or(0)
}

fn be_u16(raw: &[u8], at: usize) -> u16 {
    crate::bytes::u16_be(raw, at).unwrap_or(0)
}

/// A file header, decoded.
#[derive(Clone, Debug)]
struct FileHdr {
    span: Span,
    /// Where the extent group the header starts begins in the file.
    offset: u64,
    flags: u32,
    ino: u64,
    mode: u32,
    rdev: u32,
    size: u64,
    checksum_ok: bool,
}

impl FileHdr {
    fn kind(&self) -> u32 {
        self.mode & 0o170000
    }
}

async fn file_hdr(cx: &Cx, stream: Span, pos: u64) -> Result<FileHdr> {
    let span = stream.sub_exact(pos, FILEHDR)?;
    let raw = cx.read(span).await?;
    Ok(FileHdr {
        span,
        offset: be_u64(&raw, 0),
        flags: be_u32(&raw, 8),
        ino: be_u64(&raw, 16),
        mode: be_u32(&raw, 24),
        rdev: be_u32(&raw, 40),
        size: be_u64(&raw, 48),
        checksum_ok: checksum_ok(&raw, FILEHDR_INTS),
    })
}

/// One record of the stream: a directory with its entries, another inode
/// with its extents, extended attributes, or the end.
#[derive(Clone, Debug)]
enum Rec {
    Dir {
        hdr: FileHdr,
        entries: Vec<Dirent>,
        /// Entries, the null one ending them included, whose checksums
        /// do not match.
        bad: u64,
    },
    File {
        hdr: FileHdr,
        /// Extent headers: type, file offset, size, header span, data span.
        extents: Vec<Extent>,
    },
    Attrs {
        hdr: FileHdr,
        attrs: Vec<Attr>,
    },
    End {
        hdr: FileHdr,
    },
}

#[derive(Clone, Debug)]
struct Dirent {
    ino: u64,
    name: String,
    span: Span,
    checksum_ok: bool,
}

#[derive(Clone, Debug)]
struct Extent {
    kind: u32,
    offset: u64,
    len: u64,
    flags: u32,
    header: Span,
    data: Span,
    checksum_ok: bool,
}

#[derive(Clone, Debug)]
struct Attr {
    span: Span,
    flags: u16,
    name: String,
    value: Span,
    checksum_ok: bool,
}

impl Rec {
    fn hdr(&self) -> &FileHdr {
        match self {
            Rec::Dir { hdr, .. }
            | Rec::File { hdr, .. }
            | Rec::Attrs { hdr, .. }
            | Rec::End { hdr } => hdr,
        }
    }
}

/// Reads the record at `pos`; returns it and where the next starts.
async fn record_at(cx: &Cx, stream: Span, pos: u64) -> Result<(Rec, u64)> {
    let hdr = file_hdr(cx, stream, pos).await?;
    let mut at = pos.saturating_add(FILEHDR);
    if hdr.flags & FH_END != 0 {
        return Ok((Rec::End { hdr }, at));
    }
    if hdr.flags & FH_EXTATTR != 0 {
        let mut attrs = Vec::new();
        loop {
            cx.checkpoint().await;
            let span = stream.sub_exact(at, ATTRHDR)?;
            let raw = cx.read(span).await?;
            let len = u64::from(be_u32(&raw, 0));
            let valoff = u64::from(be_u16(&raw, 4));
            let flags = be_u16(&raw, 6);
            let valsz = u64::from(be_u32(&raw, 8));
            if len < ATTRHDR {
                return Err(
                    Diagnostic::malformed(format!("attribute record of {len} bytes")).at(span),
                );
            }
            let whole = stream.sub_exact(at, len)?;
            let body = cx.read(whole).await?;
            let name_end = crate::bytes::to_usize(valoff.min(len));
            let name = crate::text::until_nul(body.get(16..name_end).unwrap_or_default());
            attrs.push(Attr {
                span: whole,
                flags,
                name,
                value: whole.sub(valoff, valsz),
                checksum_ok: checksum_ok(&raw, ATTR_INTS),
            });
            at = at.saturating_add(len.div_ceil(8).saturating_mul(8));
            if flags & ATTR_NULL != 0 {
                break;
            }
        }
        return Ok((Rec::Attrs { hdr, attrs }, at));
    }
    match hdr.kind() {
        0o040000 => {
            let mut entries = Vec::new();
            let mut bad = 0u64;
            loop {
                cx.checkpoint().await;
                let span = stream.sub_exact(at, DIRENTHDR)?;
                let raw = cx.read(span).await?;
                let ino = be_u64(&raw, 0);
                let len = u64::from(be_u16(&raw, 16));
                if len < DIRENTHDR {
                    return Err(
                        Diagnostic::malformed(format!("directory entry of {len} bytes")).at(span),
                    );
                }
                let whole = stream.sub_exact(at, len)?;
                let body = cx.read(whole).await?;
                // Checked by the caller, if the dump has entry checksums.
                let ok = checksum_ok(&raw, DIRENT_INTS);
                if !ok {
                    bad = bad.saturating_add(1);
                }
                at = at.saturating_add(len);
                if ino == 0 {
                    break;
                }
                let name = crate::text::until_nul(body.get(18..).unwrap_or_default());
                entries.push(Dirent {
                    ino,
                    name,
                    span: whole,
                    checksum_ok: ok,
                });
            }
            Ok((Rec::Dir { hdr, entries, bad }, at))
        }
        0o100000 | 0o120000 => {
            let link = hdr.kind() == 0o120000;
            let mut extents = Vec::new();
            loop {
                cx.checkpoint().await;
                let header = stream.sub_exact(at, EXTENTHDR)?;
                let raw = cx.read(header).await?;
                let len = be_u64(&raw, 0);
                let offset = be_u64(&raw, 8);
                let kind = be_u32(&raw, 16);
                let flags = be_u32(&raw, 20);
                at = at.saturating_add(EXTENTHDR);
                let data = if kind == EXT_DATA || kind == EXT_ALIGN {
                    let d = stream.sub_exact(at, len)?;
                    at = at.saturating_add(len);
                    d
                } else {
                    stream.sub(at, 0)
                };
                extents.push(Extent {
                    kind,
                    offset,
                    len,
                    flags,
                    header,
                    data,
                    checksum_ok: checksum_ok(&raw, EXTENT_INTS),
                });
                // A symbolic link is one data extent, with no last one.
                if kind == EXT_LAST || link {
                    break;
                }
                if ![EXT_ALIGN, EXT_DATA, EXT_HOLE].contains(&kind) {
                    return Err(Diagnostic::malformed(format!("extent type {kind}")).at(header));
                }
            }
            Ok((Rec::File { hdr, extents }, at))
        }
        // Devices, FIFOs and sockets: the header is all.
        _ => Ok((
            Rec::File {
                hdr,
                extents: Vec::new(),
            },
            at,
        )),
    }
}

/// What the expanders share.
struct State {
    input: Input,
    /// The records, from after the inode map to the end of the input.
    stream: Span,
    root: u64,
    /// Whether directory entries carry checksums (dump attribute 10).
    dirent_checksums: bool,
}

/// The directory entries, read once: each inode's parent and name, and
/// where the other inodes' records start.
struct Names {
    /// Each inode's first name: its directory and the name in it.
    parent: BTreeMap<u64, (u64, String)>,
    /// The other names of hard-linked inodes.
    links: BTreeMap<u64, Vec<(u64, String)>>,
    files_at: u64,
}

/// Other names shown on a hard-linked file's node at most.
const MAX_LINKS_SHOWN: usize = 4;

impl Names {
    fn path(&self, root: u64, ino: u64) -> String {
        if ino == root {
            return "/".into();
        }
        match self.parent.get(&ino) {
            Some((dir, name)) => self.join(root, *dir, name, ino),
            None => format!("inode {ino}"),
        }
    }

    /// The paths of a hard-linked inode's other names (a few, then a
    /// count).
    fn other_paths(&self, root: u64, ino: u64) -> Vec<String> {
        let Some(links) = self.links.get(&ino) else {
            return Vec::new();
        };
        let mut out: Vec<String> = links
            .iter()
            .take(MAX_LINKS_SHOWN)
            .map(|(dir, name)| self.join(root, *dir, name, ino))
            .collect();
        if links.len() > MAX_LINKS_SHOWN {
            out.push(format!(
                "{} more",
                links.len().saturating_sub(MAX_LINKS_SHOWN)
            ));
        }
        out
    }

    /// The path of `name` in directory `dir`.
    fn join(&self, root: u64, dir: u64, name: &str, ino: u64) -> String {
        let mut parts = vec![name];
        let mut at = dir;
        while at != root && parts.len() < MAX_DEPTH {
            let Some((parent, name)) = self.parent.get(&at) else {
                return format!("inode {ino}");
            };
            parts.push(name.as_str());
            at = *parent;
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }
}

async fn names(cx: &Cx, state: &State) -> Result<Arc<Names>> {
    const KIND: &str = "xfsdump-names";
    if let Some(n) = cx.cached::<Names>(state.stream, KIND) {
        return Ok(n);
    }
    let mut parent = BTreeMap::new();
    let mut links: BTreeMap<u64, Vec<(u64, String)>> = BTreeMap::new();
    let mut pos = 0u64;
    while pos < state.stream.len {
        cx.progress_in(state.stream, pos);
        let Ok((rec, next)) = record_at(cx, state.stream, pos).await else {
            break;
        };
        match rec {
            Rec::Dir { hdr, entries, .. } => {
                for e in entries {
                    if e.name == "." || e.name == ".." {
                        continue;
                    }
                    // The first name names the inode; a hard link's
                    // others are kept for its node's summary.
                    match parent.entry(e.ino) {
                        std::collections::btree_map::Entry::Vacant(v) => {
                            v.insert((hdr.ino, e.name));
                        }
                        std::collections::btree_map::Entry::Occupied(_) => {
                            links.entry(e.ino).or_default().push((hdr.ino, e.name));
                        }
                    }
                }
            }
            Rec::Attrs { .. } => {}
            _ => break,
        }
        pos = next;
    }
    let n = Arc::new(Names {
        parent,
        links,
        files_at: pos,
    });
    cx.cache(state.stream, KIND, n.clone());
    Ok(n)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let page = cx.read(file.sub_exact(0, PAGE)?).await?;
    let g = parse(
        &cx,
        file.sub(0, GlobalHeader::SIZE),
        BE,
        &(),
        GlobalHeader::layout,
    )
    .await?;
    let check = sum_check(g.checksum, checksum_ok(&page, &[]));
    let mut global = GlobalHeader::checked_node(
        "Global header",
        file.sub(0, GlobalHeader::SIZE),
        BE,
        check.at(12),
    )
    .summary(format!("version {}, {}", g.version, g.host))
    .check_diag(&check);
    if !(1..=3).contains(&g.version) {
        global = global.diag(Diagnostic::unsupported(format!("version {}", g.version)));
    }
    cx.emit(global);
    let d = parse(
        &cx,
        file.sub(DRIVE_AT, DriveHeader::SIZE),
        BE,
        &(),
        DriveHeader::layout,
    )
    .await?;
    let mut drive = DriveHeader::node("Drive header", file.sub(DRIVE_AT, DriveHeader::SIZE), BE);
    if d.strategy != DRIVE_SIMPLE {
        drive = drive.diag(Diagnostic::unsupported(format!(
            "drive strategy {}: a tape's records, with headers of their own, are not read",
            d.strategy
        )));
    }
    cx.emit(drive);
    let m = parse(
        &cx,
        file.sub(MEDIA_AT, MediaHeader::SIZE),
        BE,
        &(),
        MediaHeader::layout,
    )
    .await?;
    cx.emit(
        MediaHeader::node("Media header", file.sub(MEDIA_AT, MediaHeader::SIZE), BE)
            .summary(format!("{:?}", m.label)),
    );
    let c = parse(
        &cx,
        file.sub(CONTENT_AT, ContentHeader::SIZE),
        BE,
        &(),
        ContentHeader::layout,
    )
    .await?;
    cx.emit(
        ContentHeader::node(
            "Content header",
            file.sub(CONTENT_AT, ContentHeader::SIZE),
            BE,
        )
        .summary(format!("{} at {}, {}", c.fs_type, c.mount_point, c.device)),
    );
    let ih_span = file.sub(INODE_AT, InodeHeader::SIZE);
    let ih = parse(&cx, ih_span, BE, &(), InodeHeader::layout).await?;
    cx.emit(
        InodeHeader::node("Inode content header", ih_span, BE).summary(format!(
            "level {}, {}, {}",
            ih.level,
            plural(ih.dirs, "directory"),
            plural(ih.nondirs, "other inode")
        )),
    );
    cx.annotate(format!(
        "xfsdump level {} of {} ({}), {}, {} and {}",
        ih.level,
        c.mount_point,
        c.fs_type,
        g.label,
        plural(ih.dirs, "directory"),
        plural(ih.nondirs, "other inode")
    ));
    let map_len = ih.hunks.saturating_mul(HUNK);
    let map = file.sub_exact(PAGE, map_len)?;
    cx.emit(
        Node::new("Inode map")
            .span(map)
            .summary(format!(
                "{}, {}",
                plural(ih.hunks, "hunk"),
                plural(ih.segments, "segment")
            ))
            .lazy(inode_map, (map, ih.segments)),
    );
    let state = Arc::new(State {
        input,
        stream: file.tail(PAGE.saturating_add(map_len)),
        root: ih.root,
        dirent_checksums: ih.attrs & DIRENT_CHECKSUMS != 0,
    });
    cx.emit(
        Node::new("Directories")
            .summary(plural(ih.dirs, "directory"))
            .lazy(directories, state.clone()),
    );
    cx.emit(
        Node::new("Files")
            .summary(plural(ih.nondirs, "inode"))
            .lazy(files, state),
    );
    Ok(())
}

/// The inode map's segments in use: 64 inodes each, with their states.
async fn inode_map(cx: Cx, (map, segments): (Span, u64)) -> Result<()> {
    let (mut index, mut shown) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let total = (map.len / HUNK).saturating_mul(SEGS_PER_HUNK);
    while index < total && shown < segments {
        let hunk = index / SEGS_PER_HUNK;
        let at = hunk
            .saturating_mul(HUNK)
            .saturating_add((index % SEGS_PER_HUNK).saturating_mul(32));
        let span = map.sub_exact(at, 32)?;
        let raw = cx.read(span).await?;
        let mark = (index, shown);
        index = index.saturating_add(1);
        let (base, lo, me, hi) = (
            be_u64(&raw, 0),
            be_u64(&raw, 8),
            be_u64(&raw, 16),
            be_u64(&raw, 24),
        );
        if base == 0 && lo == 0 && me == 0 && hi == 0 {
            continue;
        }
        shown = shown.saturating_add(1);
        let mut counts = [0u32; 8];
        for bit in 0..64u32 {
            let state = (lo >> bit & 1) | (me >> bit & 1) << 1 | (hi >> bit & 1) << 2;
            if let Some(c) = counts.get_mut(crate::bytes::to_usize(state)) {
                *c = c.saturating_add(1);
            }
        }
        let summary = counts
            .iter()
            .zip(INODE_STATES)
            .skip(1)
            .filter(|(c, _)| **c > 0)
            .map(|(c, s)| format!("{c} {s}"))
            .collect::<Vec<_>>()
            .join(", ");
        cx.mark(move || mark);
        cx.push(
            Node::new(format!("Inodes {base}–{}", base.saturating_add(63)))
                .span(span)
                .summary(if summary.is_empty() {
                    "all unused".into()
                } else {
                    summary
                }),
        )
        .await;
    }
    Ok(())
}

/// The directory records, named by path.
async fn directories(cx: Cx, state: Arc<State>) -> Result<()> {
    let names = names(&cx, &state).await?;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < names.files_at {
        let mark = (pos, index);
        let (rec, next) = match record_at(&cx, state.stream, pos).await {
            Ok(r) => r,
            Err(e) => {
                cx.mark(move || mark);
                cx.push(
                    Node::new("Unreadable record")
                        .span(state.stream.tail(pos))
                        .diag(e),
                )
                .await;
                break;
            }
        };
        // Extended attributes of a directory belong with it.
        let (attrs, after) = match record_at(&cx, state.stream, next).await {
            Ok((a @ Rec::Attrs { .. }, n)) if a.hdr().ino == rec.hdr().ino => (Some(a), n),
            _ => (None, next),
        };
        let span = state.stream.sub(pos, after.saturating_sub(pos));
        let hdr = rec.hdr();
        let mut node = Node::new(names.path(state.root, hdr.ino)).span(span);
        if let Rec::Dir { entries, .. } = &rec {
            node = node.summary(format!(
                "inode {}, {}, {}",
                hdr.ino,
                unix_mode(hdr.mode.into()),
                plural(entries.len(), "entry")
            ));
        }
        let groups = Arc::new(vec![Group { rec, span }]);
        node = record_diags(node, &state, &groups, attrs.as_ref());
        cx.mark(move || mark);
        cx.push(node.lazy(record_children, (state.clone(), groups, attrs)))
            .await;
        index = index.saturating_add(1);
        pos = after.max(pos.saturating_add(1));
    }
    Ok(())
}

/// One record of an inode with its span: a regular file is dumped as
/// extent groups, each a record of its own.
#[derive(Clone, Debug)]
struct Group {
    rec: Rec,
    span: Span,
}

/// The other inodes' records, named by path.
async fn files(cx: Cx, state: Arc<State>) -> Result<()> {
    let names = names(&cx, &state).await?;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((names.files_at, 0));
    while pos < state.stream.len {
        let mark = (pos, index);
        cx.progress_in(state.stream, pos);
        let (rec, next) = match record_at(&cx, state.stream, pos).await {
            Ok(r) => r,
            Err(e) => {
                cx.mark(move || mark);
                cx.push(
                    Node::new("Unreadable record")
                        .span(state.stream.tail(pos))
                        .diag(e),
                )
                .await;
                break;
            }
        };
        if let Rec::End { hdr } = &rec {
            let mut node = Node::new("End")
                .span(hdr.span)
                .summary("the end of the dump");
            if !hdr.checksum_ok {
                node = node.diag(Diagnostic::warning("file header checksum mismatch"));
            }
            cx.mark(move || mark);
            cx.push(node.lazy(file_header_fields, hdr.span)).await;
            let rest = state.stream.tail(next);
            if rest.len > 0 {
                cx.push(
                    Node::new("Trailing data")
                        .span(rest)
                        .summary(size(rest.len))
                        .diag(Diagnostic::warning(format!(
                            "{} after the end of the dump",
                            plural(rest.len, "byte")
                        ))),
                )
                .await;
            }
            break;
        }
        // A regular file's later extent groups, then its attributes.
        let hdr = rec.hdr().clone();
        let ino = hdr.ino;
        let regular = hdr.kind() == 0o100000;
        let mut groups = vec![Group {
            span: state.stream.sub(pos, next.saturating_sub(pos)),
            rec,
        }];
        let mut after = next;
        let mut attrs = None;
        loop {
            match record_at(&cx, state.stream, after).await {
                Ok((a @ Rec::Attrs { .. }, n)) if a.hdr().ino == ino => {
                    attrs = Some(a);
                    after = n;
                    break;
                }
                Ok((r @ Rec::File { .. }, n))
                    if regular && r.hdr().ino == ino && r.hdr().kind() == 0o100000 =>
                {
                    groups.push(Group {
                        span: state.stream.sub(after, n.saturating_sub(after)),
                        rec: r,
                    });
                    after = n.max(after.saturating_add(1));
                }
                _ => break,
            }
        }
        let span = state.stream.sub(pos, after.saturating_sub(pos));
        let kind = match hdr.kind() {
            0o100000 => "file",
            0o120000 => "symbolic link",
            0o040000 => "directory",
            0o020000 => "character device",
            0o060000 => "block device",
            0o010000 => "FIFO",
            0o140000 => "socket",
            _ => "inode",
        };
        let what = match hdr.kind() {
            0o020000 | 0o060000 => {
                let (major, minor) = dev_parts(hdr.rdev);
                format!("{major}:{minor}")
            }
            0o100000 | 0o120000 => size(hdr.size),
            _ => String::new(),
        };
        let mut summary = kind.to_string();
        for part in [
            what,
            unix_mode(hdr.mode.into()),
            format!("inode {}", hdr.ino),
        ] {
            if !part.is_empty() {
                summary.push_str(", ");
                summary.push_str(&part);
            }
        }
        let others = names.other_paths(state.root, hdr.ino);
        if !others.is_empty() {
            summary.push_str(&format!(", also {}", others.join(", ")));
        }
        let mut node = Node::new(names.path(state.root, hdr.ino))
            .span(span)
            .summary(summary);
        let groups = Arc::new(groups);
        node = record_diags(node, &state, &groups, attrs.as_ref());
        cx.mark(move || mark);
        cx.push(node.lazy(record_children, (state.clone(), groups, attrs)))
            .await;
        index = index.saturating_add(1);
        pos = after.max(pos.saturating_add(1));
    }
    Ok(())
}

/// Checksum problems of a record, on its node.
fn record_diags(mut node: Node, state: &State, groups: &[Group], attrs: Option<&Rec>) -> Node {
    for r in groups.iter().map(|g| &g.rec).chain(attrs) {
        if !r.hdr().checksum_ok {
            node = node.diag(Diagnostic::warning(format!(
                "file header checksum mismatch at {:#x}",
                r.hdr().span.offset
            )));
        }
    }
    // Extents say whether they carry a checksum (flag 1).
    if groups.iter().any(|g| {
        matches!(&g.rec, Rec::File { extents, .. }
            if extents.iter().any(|e| e.flags & 1 != 0 && !e.checksum_ok))
    }) {
        node = node.diag(Diagnostic::warning("extent header checksum mismatch"));
    }
    if state.dirent_checksums {
        for g in groups {
            if let Rec::Dir { bad, .. } = &g.rec
                && *bad > 0
            {
                node = node.diag(Diagnostic::warning(format!(
                    "{} with a checksum mismatch",
                    plural(*bad, "directory entry")
                )));
            }
        }
    }
    if let Some(Rec::Attrs { attrs, .. }) = attrs
        && attrs.iter().any(|a| !a.checksum_ok)
    {
        node = node.diag(Diagnostic::warning("attribute header checksum mismatch"));
    }
    node
}

/// A record's parts: the file header, entries or extents, attributes,
/// and a file's content. A file of several extent groups lists each.
async fn record_children(
    cx: Cx,
    (state, groups, attrs): (Arc<State>, Arc<Vec<Group>>, Option<Rec>),
) -> Result<()> {
    let Some(first) = groups.first() else {
        return Ok(());
    };
    let hdr = first.rec.hdr().clone();
    if let [one] = groups.as_slice() {
        group_parts(&cx, &state, &one.rec).await?;
    } else {
        for (i, g) in groups.iter().enumerate() {
            let n = match &g.rec {
                Rec::File { extents, .. } => extents.len(),
                _ => 0,
            };
            cx.push(
                Node::new(format!("Extent group {i}"))
                    .span(g.span)
                    .summary(format!(
                        "from offset {:#x}, {}",
                        g.rec.hdr().offset,
                        plural(n, "extent header")
                    ))
                    .lazy(group_children, (state.clone(), g.rec.clone())),
            )
            .await;
        }
    }
    if let Rec::File { extents, .. } = &first.rec {
        if hdr.kind() == 0o120000 {
            if let Some(e) = extents.first() {
                let raw = cx.read(e.data).await?;
                cx.push(
                    Node::new("Link target")
                        .span(e.data)
                        .value(text(crate::text::until_nul(&raw))),
                )
                .await;
            }
        } else if hdr.kind() == 0o100000 {
            cx.push(
                Node::new("Content")
                    .summary(size(hdr.size))
                    .lazy(content, (state.clone(), groups.clone())),
            )
            .await;
        }
    }
    if let Some(Rec::Attrs { hdr, attrs }) = &attrs {
        let count = attrs.iter().filter(|a| a.flags & ATTR_NULL == 0).count();
        let end = attrs.last().map_or(hdr.span.end(), |a| a.span.end());
        cx.push(
            Node::new("Extended attributes")
                .span(Span::new(
                    hdr.span.source,
                    hdr.span.offset,
                    end.saturating_sub(hdr.span.offset),
                ))
                .summary(if count == 0 {
                    "none".to_string()
                } else {
                    plural(count, "attribute")
                })
                .lazy(attributes, (hdr.span, attrs.clone())),
        )
        .await;
    }
    Ok(())
}

/// An inode's extended attributes record: its file header, the
/// attributes (POSIX ACLs as `getfacl` text) and the null one ending them.
async fn attributes(cx: Cx, (hdr, attrs): (Span, Vec<Attr>)) -> Result<()> {
    cx.push(Node::new("Header").span(hdr).lazy(file_header_fields, hdr))
        .await;
    for a in attrs.iter() {
        let name = if a.flags & ATTR_NULL != 0 {
            "End of attributes".to_string()
        } else {
            let ns = if a.flags & 1 != 0 {
                "trusted."
            } else if a.flags & 8 != 0 {
                "security."
            } else {
                "user."
            };
            format!("Attribute {ns}{}", a.name)
        };
        let mut node = Node::new(name)
            .span(a.span)
            .lazy(attr_fields, (a.span, a.value));
        if a.flags & ATTR_NULL == 0 {
            let acl = a.flags & 1 != 0
                && (a.name == "SGI_ACL_FILE" || a.name == "SGI_ACL_DEFAULT")
                && a.value.len <= MAX_ACL;
            let text = if acl {
                crate::formats::disk::xfs::acl_text(&cx.read(a.value).await?)
            } else {
                None
            };
            node = node.summary(match text {
                Some(t) => format!("POSIX ACL: {t}"),
                None => size(a.value.len),
            });
        }
        cx.push(node).await;
    }
    Ok(())
}

/// ACL values larger than this are not decoded for the summary (XFS
/// allows a few thousand entries of 12 bytes).
const MAX_ACL: u64 = 1 << 16;

async fn group_children(cx: Cx, (state, rec): (Arc<State>, Rec)) -> Result<()> {
    group_parts(&cx, &state, &rec).await
}

/// A record's file header, then its directory entries or extent headers.
async fn group_parts(cx: &Cx, state: &State, rec: &Rec) -> Result<()> {
    let hdr = rec.hdr();
    cx.emit(
        Node::new("File header")
            .span(hdr.span)
            .lazy(file_header_fields, hdr.span),
    );
    match rec {
        Rec::Dir { entries, .. } => {
            for e in entries {
                let mut node = Node::new(e.name.clone())
                    .span(e.span)
                    .summary(format!("inode {}", e.ino))
                    .lazy(dirent_fields, (e.span, state.dirent_checksums));
                if state.dirent_checksums && !e.checksum_ok {
                    node = node.diag(Diagnostic::warning("directory entry checksum mismatch"));
                }
                cx.push(node).await;
            }
        }
        Rec::File { extents, .. } => {
            for e in extents {
                let name = crate::formats::util::val::name_or(EXTENT_TYPES, e.kind.into(), "type ");
                let mut node = Node::new(format!("Extent: {name}"))
                    .span(Span::new(
                        e.header.source,
                        e.header.offset,
                        e.data.end().saturating_sub(e.header.offset),
                    ))
                    .lazy(extent_fields, e.header);
                node = match e.kind {
                    EXT_DATA | EXT_HOLE => {
                        node.summary(format!("{} at offset {:#x}", size(e.len), e.offset))
                    }
                    EXT_ALIGN => node.summary(format!("{} of padding", size(e.len))),
                    _ => node,
                };
                if e.flags & 1 != 0 && !e.checksum_ok {
                    node = node.diag(Diagnostic::warning("extent header checksum mismatch"));
                }
                cx.push(node).await;
            }
        }
        Rec::Attrs { .. } | Rec::End { .. } => {}
    }
    Ok(())
}

/// A regular file's content: its data extents and holes, clipped to its
/// size.
async fn content(cx: Cx, (state, groups): (Arc<State>, Arc<Vec<Group>>)) -> Result<()> {
    let Some(Group {
        rec: Rec::File { hdr, .. },
        ..
    }) = groups.first()
    else {
        return Ok(());
    };
    let extents = groups.iter().flat_map(|g| match &g.rec {
        Rec::File { extents, .. } => extents.as_slice(),
        _ => &[],
    });
    let mut list = PieceList::new(hdr.span);
    for (i, e) in extents.enumerate() {
        if i % 1024 == 0 {
            cx.checkpoint().await;
        }
        if e.offset > list.len() && matches!(e.kind, EXT_DATA | EXT_HOLE) {
            list.hole(&cx, e.offset.saturating_sub(list.len()))?;
        }
        let left = hdr.size.saturating_sub(list.len());
        match e.kind {
            EXT_DATA => list.data(e.data.sub(0, e.len.min(left))),
            EXT_HOLE => list.hole(&cx, e.len.min(left))?,
            _ => {}
        }
    }
    if list.len() < hdr.size {
        list.hole(&cx, hdr.size.saturating_sub(list.len()))?;
    }
    let span = if list.is_empty() {
        Span::new(hdr.span.source, hdr.span.end(), 0)
    } else {
        cx.add_pieces_stepped(
            Origin {
                parent: hdr.span,
                transform: "xfsdump-file",
            },
            list.pieces(),
        )
        .await?
    };
    dissect_or_data(cx, state.input.nested(span)).await
}

async fn file_header_fields(cx: Cx, span: Span) -> Result<()> {
    let raw = cx.read(span).await?;
    let mut f = Node::new("Offset")
        .span(span.sub(0, 8))
        .value(uint(be_u64(&raw, 0), 64));
    f = f.desc("Where the extent group this header starts begins in the file (a large file is dumped as several)");
    cx.emit(f);
    let flags = be_u32(&raw, 8);
    cx.emit(
        Node::new("Flags")
            .span(span.sub(8, 4))
            .value(crate::formats::util::val::flagsv(flags, 32, FILE_FLAGS)),
    );
    cx.emit(
        Node::new("Checksum")
            .span(span.sub(12, 4))
            .checksum(sum_check(be_u32(&raw, 12), checksum_ok(&raw, FILEHDR_INTS))),
    );
    if flags & (FH_NULL | FH_END) != 0 && be_u64(&raw, 16) == 0 {
        return Ok(());
    }
    let st = span.sub(16, 128);
    let u32_at = |o: u64| be_u32(&raw, crate::bytes::to_usize(o));
    let u64_at = |o: u64| be_u64(&raw, crate::bytes::to_usize(o));
    let time = |o: u64| Value::utc(i64::from(i32::from_be_bytes(u32_at(o).to_be_bytes())));
    let fields: Vec<Node> = vec![
        Node::new("Inode")
            .span(st.sub(0, 8))
            .value(uint(u64_at(16), 64)),
        Node::new("Mode")
            .span(st.sub(8, 4))
            .value(crate::formats::util::val::oct(u32_at(24), 32))
            .summary(unix_mode(u32_at(24).into())),
        Node::new("Links")
            .span(st.sub(12, 4))
            .value(uint(u32_at(28), 32)),
        Node::new("User id")
            .span(st.sub(16, 4))
            .value(uint(u32_at(32), 32)),
        Node::new("Group id")
            .span(st.sub(20, 4))
            .value(uint(u32_at(36), 32)),
        {
            let (major, minor) = dev_parts(u32_at(40));
            let n = Node::new("Device")
                .span(st.sub(24, 4))
                .value(hex(u32_at(40), 32));
            if u32_at(40) == 0 {
                n
            } else {
                n.summary(format!("{major}:{minor}"))
            }
        },
        Node::new("Block size")
            .span(st.sub(28, 4))
            .value(uint(u32_at(44), 32)),
        Node::new("Size")
            .span(st.sub(32, 8))
            .value(uint(u64_at(48), 64))
            .summary(size(u64_at(48))),
        Node::new("Accessed").span(st.sub(40, 8)).value(time(56)),
        Node::new("Modified").span(st.sub(48, 8)).value(time(64)),
        Node::new("Changed").span(st.sub(56, 8)).value(time(72)),
        Node::new("Blocks")
            .span(st.sub(64, 8))
            .value(uint(u64_at(80), 64)),
        Node::new("Extended flags")
            .span(st.sub(72, 4))
            .value(crate::formats::util::val::flagsv(u32_at(88), 32, XFLAGS)),
        Node::new("Extent size hint")
            .span(st.sub(76, 4))
            .value(uint(u32_at(92), 32)),
        Node::new("Extents")
            .span(st.sub(80, 4))
            .value(uint(u32_at(96), 32)),
        Node::new("Generation")
            .span(st.sub(84, 4))
            .value(hex(u32_at(100), 32)),
        Node::new("Project id").span(st.sub(88, 6)).value(uint(
            u32::from(be_u16(&raw, 108)) << 16 | u32::from(be_u16(&raw, 104)),
            32,
        )),
        Node::new("Fork offset")
            .span(st.sub(90, 2))
            .value(uint(be_u16(&raw, 106), 16)),
        Node::new("DMAPI event mask")
            .span(st.sub(104, 4))
            .value(hex(u32_at(120), 32)),
        Node::new("DMAPI state")
            .span(st.sub(108, 2))
            .value(hex(be_u16(&raw, 124), 16)),
    ];
    for f in fields {
        cx.push(f).await;
    }
    Ok(())
}

async fn extent_fields(cx: Cx, span: Span) -> Result<()> {
    let raw = cx.read(span).await?;
    cx.emit(
        Node::new("Size")
            .span(span.sub(0, 8))
            .value(uint(be_u64(&raw, 0), 64)),
    );
    cx.emit(
        Node::new("Offset")
            .span(span.sub(8, 8))
            .value(hex(be_u64(&raw, 8), 64)),
    );
    cx.emit(
        Node::new("Type")
            .span(span.sub(16, 4))
            .value(crate::formats::util::val::enumv(
                be_u32(&raw, 16),
                32,
                EXTENT_TYPES,
            )),
    );
    cx.emit(
        Node::new("Flags")
            .span(span.sub(20, 4))
            .value(hex(be_u32(&raw, 20), 32)),
    );
    cx.emit(
        Node::new("Checksum")
            .span(span.sub(24, 4))
            .checksum(sum_check(be_u32(&raw, 24), checksum_ok(&raw, EXTENT_INTS))),
    );
    Ok(())
}

async fn dirent_fields(cx: Cx, (span, checked): (Span, bool)) -> Result<()> {
    let raw = cx.read(span).await?;
    cx.emit(
        Node::new("Inode")
            .span(span.sub(0, 8))
            .value(uint(be_u64(&raw, 0), 64)),
    );
    cx.emit(
        Node::new("Generation")
            .span(span.sub(8, 4))
            .value(hex(be_u32(&raw, 8), 32)),
    );
    let ck = Node::new("Checksum").span(span.sub(12, 4));
    cx.emit(if checked {
        ck.checksum(sum_check(
            be_u32(&raw, 12),
            checksum_ok(raw.get(..24).unwrap_or_default(), DIRENT_INTS),
        ))
    } else {
        ck.value(hex(be_u32(&raw, 12), 32))
    });
    cx.emit(
        Node::new("Record size")
            .span(span.sub(16, 2))
            .value(uint(be_u16(&raw, 16), 16)),
    );
    cx.emit(
        Node::new("Name")
            .span(span.tail(18))
            .value(text(crate::text::until_nul(
                raw.get(18..).unwrap_or_default(),
            ))),
    );
    Ok(())
}

async fn attr_fields(cx: Cx, (span, value): (Span, Span)) -> Result<()> {
    let raw = cx.read(span.sub(0, ATTRHDR)).await?;
    cx.emit(
        Node::new("Record size")
            .span(span.sub(0, 4))
            .value(uint(be_u32(&raw, 0), 32)),
    );
    cx.emit(
        Node::new("Value offset")
            .span(span.sub(4, 2))
            .value(uint(be_u16(&raw, 4), 16)),
    );
    cx.emit(
        Node::new("Flags")
            .span(span.sub(6, 2))
            .value(crate::formats::util::val::flagsv(
                be_u16(&raw, 6),
                16,
                ATTR_FLAGS,
            )),
    );
    cx.emit(
        Node::new("Value size")
            .span(span.sub(8, 4))
            .value(uint(be_u32(&raw, 8), 32)),
    );
    cx.emit(
        Node::new("Checksum")
            .span(span.sub(12, 4))
            .checksum(sum_check(be_u32(&raw, 12), checksum_ok(&raw, ATTR_INTS))),
    );
    if be_u16(&raw, 6) & ATTR_NULL == 0 {
        let name_end = value.offset.saturating_sub(span.offset);
        let name = cx
            .read(span.sub(ATTRHDR, name_end.saturating_sub(ATTRHDR)))
            .await?;
        cx.emit(
            Node::new("Name")
                .span(span.sub(ATTRHDR, name_end.saturating_sub(ATTRHDR)))
                .value(text(crate::text::until_nul(&name))),
        );
        let v = cx.read_avail(value.sub(0, 4096)).await?;
        let shown = if crate::text::looks_like_text(&v) {
            text(String::from_utf8_lossy(&v).into_owned())
        } else {
            Value::Bytes(v)
        };
        cx.emit(Node::new("Value").span(value).value(shown));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// The null directory entry ending a directory, as xfsdump 3.2.0 writes
    /// it on a little-endian machine: its 16-bit size makes the checksum
    /// depend on the writer's layout.
    #[test]
    fn dirent_checksums_use_the_writers_layout() {
        let mut null = vec![0u8; 16];
        null.extend_from_slice(&24u16.to_be_bytes());
        null.extend_from_slice(&[0; 6]);
        // The null entry's checksum: minus the sum of its little-endian
        // words (the size, 24, is the low half of the fifth word).
        let ck = 0u32.wrapping_sub(24);
        null[12..16].copy_from_slice(&ck.to_be_bytes());
        assert!(checksum_ok(&null, DIRENT_INTS));
        null[20] ^= 1;
        assert!(!checksum_ok(&null, DIRENT_INTS));
        // Written by a big-endian machine: the words as stored sum to zero.
        let mut be = vec![0u8; 24];
        be[16..18].copy_from_slice(&24u16.to_be_bytes());
        let ck = 0u32.wrapping_sub(24 << 16);
        be[12..16].copy_from_slice(&ck.to_be_bytes());
        assert!(checksum_ok(&be, DIRENT_INTS));
    }
}
