//! Inno Setup installers: the setup loader's offset table and the data it
//! locates in `setup.exe` (or a standalone `setup-0.bin`).
//!
//! The loader (`setup.exe`) keeps a 44-byte offset table in resource
//! `RCDATA #11111` (Inno Setup 5.1.5 and later; ID `rDlPtS` + 6 bytes,
//! version, total size, the compressed setup program `setup.e32` with its
//! size and CRC, `Offset0`, `Offset1`, and a CRC-32 of the table) or, in
//! older versions, at the file offset stored at 0x30 after `Inno`.
//! `Offset0` holds the setup data (`setup-0`):
//!
//! - a 64-byte version string, `Inno Setup Setup Data (6.2.2) (u)`;
//! - a *compressed block*: a CRC-32 of the next 9 bytes, the stored size
//!   and a compressed flag, then the stored bytes in 4 KiB chunks, each
//!   preceded by its CRC-32; the chunks joined are LZMA (5 property bytes,
//!   then the raw stream) or, before 4.1.6, zlib. It holds the setup header
//!   (`TSetupHeader`: length-prefixed strings such as AppName, AppVersion
//!   and AppPublisher, the entry counts, then settings) followed by the
//!   entries: languages, custom messages, permissions, types, components,
//!   tasks, directories, files, icons, INI and registry entries, ...;
//! - a second compressed block with the file location entries
//!   (`TSetupFileLocationEntry`: slices, the chunk's offset, the file's
//!   offset and size in the decompressed chunk, the chunk's compressed
//!   size, SHA-1, time stamp, version, flags).
//!
//! `Offset1` is where the file data starts: chunks (`zlb\x1a`, then the
//! compressed data: zlib, bzip2, LZMA with 5 property bytes or LZMA2 with
//! one), each holding one or more files back to back.
//!
//! Supported: Inno Setup 5.5.0 to 6.2.x, ANSI and Unicode builds (strings
//! are UTF-16 in Unicode builds, which all 6.x builds are). Other versions
//! show the loader table, the version and the decompressed blocks only.
//! There is no public specification: layouts are from memory of Inno
//! Setup's `Struct.pas` and of innoextract. Several record tails end in
//! Delphi sets whose size depends on the version; where our expected size
//! does not lead to a parseable next record, nearby sizes are tried and the
//! tail is shown raw. Only our synthetic fixtures (no Inno Setup compiler
//! here) were checked.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::codec::lzma::Props;
use crate::codec::{Codec, crc32, decode_span, read_all};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{count, emit_nodes, hex, text, uint};
use crate::formats::{Input, Probe, dissect_or_data};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

use super::{filetime, size};

const LE: Endian = Endian::Little;

/// Offset table IDs: 5.1.5 and later, and 4.x to 5.1.4.
const ID_NEW: &[u8] = b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a";
const ID_OLD: &[u8] = b"rDlPtS02\x87eVx";
const TABLE: u64 = 44;
const VERSION_LEN: u64 = 64;
const CHUNK: u64 = 4096;

declare_format!(pub FORMAT = "inno-setup", "Inno Setup installer data", ["exe", "bin"], "application/x-inno-setup",
    Probe::Magic(&[(0, ID_OLD), (0, ID_NEW), (0, b"Inno Setup Setup Data (")]), dissect);

/// The loader's offset table in a PE file: in the resource found at
/// `RCDATA #11111` (`resource`), or where the 32-bit value after `Inno`
/// at 0x30 says.
pub async fn loader_table(cx: &Cx, file: Span, resource: Option<Span>) -> Option<Span> {
    if let Some(r) = resource {
        let head = cx.read_avail(r.sub(0, 12)).await.ok()?;
        if head == ID_NEW || head == ID_OLD {
            return Some(r.sub(0, TABLE));
        }
    }
    let at = cx.read_avail(file.sub(0x30, 12)).await.ok()?;
    let offset = u32_le(&at, 4)?;
    if at.get(..4) != Some(b"Inno") || u32_le(&at, 8) != Some(!offset) {
        return None;
    }
    let table = file.sub_exact(offset.into(), TABLE).ok()?;
    let head = cx.read_avail(table.sub(0, 12)).await.ok()?;
    (head == ID_NEW || head == ID_OLD).then_some(table)
}

// ---------------------------------------------------------------------------
// Versions

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    major: u8,
    minor: u8,
    patch: u8,
}

const fn v(major: u8, minor: u8, patch: u8) -> Version {
    Version {
        major,
        minor,
        patch,
    }
}

/// `Inno Setup Setup Data (5.5.7) (u)`: the version and whether the build
/// is Unicode.
fn parse_version(s: &str) -> Option<(Version, bool)> {
    let open = s.find('(')?;
    let rest = s.get(open.saturating_add(1)..)?;
    let close = rest.find(')')?;
    let mut parts = rest
        .get(..close)?
        .split('.')
        .map(|p| p.trim().parse::<u8>());
    let major = parts.next()?.ok()?;
    let minor = parts.next()?.ok()?;
    let patch = parts.next().and_then(|p| p.ok()).unwrap_or(0);
    let unicode = rest.to_ascii_lowercase().contains("(u)") || major >= 6;
    Some((v(major, minor, patch), unicode))
}

fn supported(ver: Version) -> bool {
    ver >= v(5, 5, 0) && ver < v(6, 3, 0)
}

// ---------------------------------------------------------------------------
// Compressed blocks

/// A compressed block: its header, chunk region and decoded bytes.
struct BlockInfo {
    /// Header, CRCs and chunks.
    span: Span,
    stored: u64,
    compressed: bool,
    /// The decoded block (or why it could not be decoded).
    decoded: Result<Span>,
    problem: Option<Diagnostic>,
}

/// Reads the block at `at` of `data`: header, chunks joined, decoded.
async fn block(cx: &Cx, data: Span, at: u64, ver: Version) -> Result<BlockInfo> {
    let head = cx.read(data.sub(at, 9)).await?;
    let stored = u64::from(u32_le(&head, 4).unwrap_or(0));
    let compressed = head.get(8).copied().unwrap_or(0) != 0;
    let region = data.sub(at.saturating_add(9), stored);
    let span = data.sub(at, stored.saturating_add(9));
    let mut problem = None;
    if crc32(head.get(4..9).unwrap_or_default()) != u32_le(&head, 0).unwrap_or(0) {
        problem = Some(Diagnostic::warning("block header CRC mismatch"));
    }
    // The payload without the chunk CRCs.
    let mut pieces = Vec::new();
    let mut pos = 0u64;
    while pos < region.len {
        if pieces.len().is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let piece = region.sub(pos.saturating_add(4), CHUNK);
        if piece.len == 0 {
            break;
        }
        pieces.push(piece);
        pos = pos.saturating_add(4).saturating_add(CHUNK);
        if pieces.len() >= 1 << 16 {
            return Err(Diagnostic::limit("too many chunks"));
        }
    }
    let payload = cx
        .add_pieces_stepped(
            Origin {
                parent: region,
                transform: "inno-block-chunks",
            },
            &pieces,
        )
        .await?;

    let decoded = if !compressed {
        Ok(payload)
    } else {
        let codec = if ver >= v(4, 1, 6) {
            lzma_codec(cx, payload).await
        } else {
            Ok((Codec::Zlib, payload))
        };
        match codec {
            Ok((codec, from)) => match decode_span(cx, from, &codec, None).await {
                Ok(d) => {
                    if let Some(e) = d.error {
                        problem = Some(e);
                    }
                    Ok(d.span)
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    };
    Ok(BlockInfo {
        span,
        stored,
        compressed,
        decoded,
        problem,
    })
}

/// LZMA with its 5-byte header (properties, dictionary size).
async fn lzma_codec(cx: &Cx, span: Span) -> Result<(Codec, Span)> {
    let head = cx.read(span.sub(0, 5)).await?;
    let props = Props::from_byte(head.first().copied().unwrap_or(0))?;
    Ok((
        Codec::LzmaRaw {
            props,
            size: None,
            dict: u32_le(&head, 1),
        },
        span.tail(5),
    ))
}

// ---------------------------------------------------------------------------
// Records

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Str {
    /// `String`: UTF-16 in Unicode builds.
    Wide,
    /// `AnsiString`: bytes.
    Ansi,
}

/// A kind of entry: its strings and the size of the fixed fields after
/// them (Unicode builds, ANSI builds).
struct Kind {
    name: &'static str,
    one: &'static str,
    many: &'static str,
    strings: &'static [(&'static str, Str)],
    tail: (usize, usize),
}

const fn kind(
    name: &'static str,
    (one, many): (&'static str, &'static str),
    strings: &'static [(&'static str, Str)],
    tail: (usize, usize),
) -> Kind {
    Kind {
        name,
        one,
        many,
        strings,
        tail,
    }
}

use Str::{Ansi, Wide};

const LANGUAGES: Kind = kind(
    "Languages",
    ("language", "languages"),
    &[
        ("Name", Wide),
        ("LanguageName", Wide),
        ("DialogFontName", Wide),
        ("TitleFontName", Wide),
        ("WelcomeFontName", Wide),
        ("CopyrightFontName", Wide),
        ("Data", Ansi),
        ("LicenseText", Ansi),
        ("InfoBeforeText", Ansi),
        ("InfoAfterText", Ansi),
    ],
    (21, 25),
);
const MESSAGES: Kind = kind(
    "Custom messages",
    ("message", "messages"),
    &[("Name", Wide), ("Value", Wide)],
    (4, 4),
);
const PERMISSIONS: Kind = kind(
    "Permissions",
    ("permission set", "permission sets"),
    &[("Permissions", Ansi)],
    (0, 0),
);
const TYPES: Kind = kind(
    "Types",
    ("type", "types"),
    &[
        ("Name", Wide),
        ("Description", Wide),
        ("Languages", Wide),
        ("Check", Wide),
    ],
    (30, 30),
);
const COMPONENTS: Kind = kind(
    "Components",
    ("component", "components"),
    &[
        ("Name", Wide),
        ("Description", Wide),
        ("Types", Wide),
        ("Languages", Wide),
        ("Check", Wide),
    ],
    (42, 42),
);
const TASKS: Kind = kind(
    "Tasks",
    ("task", "tasks"),
    &[
        ("Name", Wide),
        ("Description", Wide),
        ("GroupDescription", Wide),
        ("Components", Wide),
        ("Languages", Wide),
        ("Check", Wide),
    ],
    (26, 26),
);
const DIRECTORIES: Kind = kind(
    "Directories",
    ("directory", "directories"),
    &[
        ("DirName", Wide),
        ("Components", Wide),
        ("Tasks", Wide),
        ("Languages", Wide),
        ("Check", Wide),
        ("AfterInstall", Wide),
        ("BeforeInstall", Wide),
    ],
    (27, 27),
);
const FILES: Kind = kind(
    "File entries",
    ("file entry", "file entries"),
    &[
        ("Source", Wide),
        ("DestName", Wide),
        ("InstallFontName", Wide),
        ("StrongAssemblyName", Wide),
        ("Components", Wide),
        ("Tasks", Wide),
        ("Languages", Wide),
        ("Check", Wide),
        ("AfterInstall", Wide),
        ("BeforeInstall", Wide),
    ],
    (43, 43),
);
/// Only used to check where the file entries end.
const ICONS: Kind = kind(
    "Icons",
    ("icon", "icons"),
    &[
        ("IconName", Wide),
        ("Filename", Wide),
        ("Parameters", Wide),
        ("WorkingDir", Wide),
    ],
    (0, 0),
);

/// The entry tables we parse, with the index of their count in the
/// header's counts.
const TABLES: [(&Kind, usize); 8] = [
    (&LANGUAGES, 0),
    (&MESSAGES, 1),
    (&PERMISSIONS, 2),
    (&TYPES, 3),
    (&COMPONENTS, 4),
    (&TASKS, 5),
    (&DIRECTORIES, 6),
    (&FILES, 7),
];
const ICON_COUNT: usize = 9;

const COUNTS: [&str; 16] = [
    "Languages",
    "Custom messages",
    "Permissions",
    "Types",
    "Components",
    "Tasks",
    "Directories",
    "Files",
    "File locations",
    "Icons",
    "INI entries",
    "Registry entries",
    "Install delete entries",
    "Uninstall delete entries",
    "Run entries",
    "Uninstall run entries",
];

/// A string field: where its length prefix starts, the bytes after it,
/// and the text.
#[derive(Clone, Debug)]
struct Field {
    at: usize,
    len: usize,
    text: String,
}

/// A parsed entry: its strings and its fixed fields (`tail..end`).
#[derive(Clone, Debug)]
struct Entry {
    start: usize,
    strings: Vec<Field>,
    tail: usize,
    end: usize,
}

struct Table {
    kind: &'static Kind,
    entries: Vec<Entry>,
    /// Whether the fixed fields had the size we expected.
    expected: bool,
}

/// Reads a length-prefixed string at `pos`.
fn read_str(buf: &[u8], pos: usize, kind: Str, unicode: bool) -> Option<(Field, usize)> {
    let len = to_usize(u32_le(buf, pos)?.into());
    let start = pos.checked_add(4)?;
    let end = start.checked_add(len)?;
    let bytes = buf.get(start..end)?;
    let wide = unicode && kind == Wide;
    if wide && !len.is_multiple_of(2) {
        return None;
    }
    let text = if wide {
        crate::text::utf16(bytes, LE)
    } else {
        crate::text::latin1(bytes)
    };
    Some((Field { at: pos, len, text }, end))
}

/// Parses one entry with a fixed part of `tail` bytes.
fn read_entry(buf: &[u8], pos: usize, kind: &Kind, unicode: bool, tail: usize) -> Option<Entry> {
    let mut strings = Vec::with_capacity(kind.strings.len());
    let mut p = pos;
    for &(_, k) in kind.strings {
        let (f, next) = read_str(buf, p, k, unicode)?;
        strings.push(f);
        p = next;
    }
    let end = p.checked_add(tail)?;
    (end <= buf.len()).then_some(Entry {
        start: pos,
        strings,
        tail: p,
        end,
    })
}

/// Whether the strings of an entry of `kind` (up to four) parse at `pos`.
fn plausible(buf: &[u8], pos: usize, kind: Option<&Kind>, unicode: bool) -> bool {
    match kind {
        Some(k) => {
            let mut p = pos;
            for &(_, s) in k.strings.iter().take(4) {
                match read_str(buf, p, s, unicode) {
                    Some((_, next)) => p = next,
                    None => return false,
                }
            }
            true
        }
        // Something follows that we do not parse: a length or count that
        // fits, or the end.
        None => {
            pos == buf.len() || u32_le(buf, pos).is_some_and(|n| to_usize(n.into()) <= buf.len())
        }
    }
}

/// Fixed-part sizes to try: the expected one first, then nearby ones.
fn candidates(expected: usize) -> impl Iterator<Item = (usize, bool)> {
    [0i64, 1, -1, 2, -2, 3, -3, 4, -4]
        .into_iter()
        .filter_map(move |d| {
            let t = i64::try_from(expected).ok()?.checked_add(d)?;
            Some((usize::try_from(t).ok()?, d == 0))
        })
}

/// Parses `n` entries of `kind` at `pos`, with the fixed-part size that
/// lets the next record (`next`) parse after them.
async fn read_table(
    cx: &Cx,
    buf: &[u8],
    pos: usize,
    n: u32,
    kind: &'static Kind,
    unicode: bool,
    next: Option<&Kind>,
) -> Option<(Table, usize)> {
    let expected = if unicode { kind.tail.0 } else { kind.tail.1 };
    for (tail, exact) in candidates(expected) {
        let mut entries = Vec::new();
        let mut p = pos;
        let mut ok = true;
        for i in 0..n {
            // `n` is bounded only by the (decoded) header's size.
            if i.is_multiple_of(256) {
                cx.checkpoint().await;
            }
            match read_entry(buf, p, kind, unicode, tail) {
                Some(e) => {
                    p = e.end;
                    entries.push(e);
                }
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && (n == 0 || plausible(buf, p, next, unicode)) {
            return Some((
                Table {
                    kind,
                    entries,
                    expected: exact,
                },
                p,
            ));
        }
        if n == 0 {
            break;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// The setup header

/// Header strings for 5.5.0 and later (the version that introduced each).
const HEADER_STRINGS: &[(&str, Version)] = &[
    ("AppName", v(0, 0, 0)),
    ("AppVerName", v(0, 0, 0)),
    ("AppId", v(0, 0, 0)),
    ("AppCopyright", v(0, 0, 0)),
    ("AppPublisher", v(0, 0, 0)),
    ("AppPublisherURL", v(0, 0, 0)),
    ("AppSupportPhone", v(0, 0, 0)),
    ("AppSupportURL", v(0, 0, 0)),
    ("AppUpdatesURL", v(0, 0, 0)),
    ("AppVersion", v(0, 0, 0)),
    ("DefaultDirName", v(0, 0, 0)),
    ("DefaultGroupName", v(0, 0, 0)),
    ("BaseFilename", v(0, 0, 0)),
    ("UninstallFilesDir", v(0, 0, 0)),
    ("UninstallDisplayName", v(0, 0, 0)),
    ("UninstallDisplayIcon", v(0, 0, 0)),
    ("AppMutex", v(0, 0, 0)),
    ("DefaultUserInfoName", v(0, 0, 0)),
    ("DefaultUserInfoOrg", v(0, 0, 0)),
    ("DefaultUserInfoSerial", v(0, 0, 0)),
    ("AppReadmeFile", v(0, 0, 0)),
    ("AppContact", v(0, 0, 0)),
    ("AppComments", v(0, 0, 0)),
    ("AppModifyPath", v(0, 0, 0)),
    ("CreateUninstallRegKey", v(0, 0, 0)),
    ("Uninstallable", v(0, 0, 0)),
    ("CloseApplicationsFilter", v(0, 0, 0)),
    ("SetupMutex", v(5, 5, 6)),
    ("ChangesEnvironment", v(5, 6, 1)),
    ("ChangesAssociations", v(5, 6, 1)),
];
const HEADER_ANSI: [&str; 4] = [
    "LicenseText",
    "InfoBeforeText",
    "InfoAfterText",
    "CompiledCodeText",
];

/// The settings after the counts: name and size, for `ver`. The last
/// (`Options`, a set) takes what is left.
fn settings(ver: Version) -> Vec<(&'static str, usize)> {
    let mut out = vec![
        ("MinVersion", 10),
        ("OnlyBelowVersion", 10),
        ("BackColor", 4),
        ("BackColor2", 4),
    ];
    if ver < v(5, 5, 7) {
        out.push(("WizardImageBackColor", 4));
    }
    if ver >= v(6, 0, 0) {
        out.extend([
            ("WizardStyle", 1),
            ("WizardSizePercentX", 4),
            ("WizardSizePercentY", 4),
        ]);
    }
    if ver >= v(5, 5, 7) {
        out.push(("ImageAlphaFormat", 1));
    }
    out.extend([
        ("PasswordHash", 20),
        ("PasswordSalt", 8),
        ("ExtraDiskSpaceRequired", 8),
        ("SlicesPerDisk", 4),
        ("UninstallLogMode", 1),
        ("DirExistsWarning", 1),
        ("PrivilegesRequired", 1),
    ]);
    if ver >= v(6, 0, 0) {
        out.push(("PrivilegesRequiredOverridesAllowed", 1));
    }
    out.extend([
        ("ShowLanguageDialog", 1),
        ("LanguageDetectionMethod", 1),
        ("CompressMethod", 1),
        ("ArchitecturesAllowed", 1),
        ("ArchitecturesInstallIn64BitMode", 1),
        ("DisableDirPage", 1),
        ("DisableProgramGroupPage", 1),
        ("UninstallDisplaySize", 8),
    ]);
    out.push(("Options", if ver >= v(6, 0, 0) { 7 } else { 6 }));
    out
}

const COMPRESSION: EnumTable = &[
    (0, "stored"),
    (1, "zlib"),
    (2, "bzip2"),
    (3, "LZMA"),
    (4, "LZMA2"),
];
const PRIVILEGES: EnumTable = &[(0, "none"), (1, "poweruser"), (2, "admin"), (3, "lowest")];
const YES_NO_AUTO: EnumTable = &[(0, "auto"), (1, "no"), (2, "yes")];

const FILE_FLAGS: FlagTable = &[
    flag(1 << 0, "ConfirmOverwrite"),
    flag(1 << 1, "UninsNeverUninstall"),
    flag(1 << 2, "RestartReplace"),
    flag(1 << 3, "DeleteAfterInstall"),
    flag(1 << 4, "RegisterServer"),
    flag(1 << 5, "RegisterTypeLib"),
    flag(1 << 6, "SharedFile"),
    flag(1 << 7, "CompareTimeStamp"),
    flag(1 << 8, "FontIsntTrueType"),
    flag(1 << 9, "SkipIfSourceDoesntExist"),
    flag(1 << 10, "OverwriteReadOnly"),
    flag(1 << 11, "OverwriteSameVersion"),
    flag(1 << 12, "CustomDestName"),
    flag(1 << 13, "OnlyIfDestFileExists"),
    flag(1 << 14, "NoRegError"),
    flag(1 << 15, "UninsRestartDelete"),
    flag(1 << 16, "OnlyIfDoesntExist"),
    flag(1 << 17, "IgnoreVersion"),
    flag(1 << 18, "PromptIfOlder"),
    flag(1 << 19, "DontCopy"),
    flag(1 << 20, "UninsRemoveReadOnly"),
    flag(1 << 21, "RecurseSubDirsExternal"),
    flag(1 << 22, "ReplaceSameVersionIfContentsDiffer"),
    flag(1 << 23, "DontVerifyChecksum"),
    flag(1 << 24, "UninsNoSharedFilePrompt"),
    flag(1 << 25, "CreateAllSubDirs"),
    flag(1 << 26, "32bit"),
    flag(1 << 27, "64bit"),
    flag(1 << 28, "ExternalSizePreset"),
    flag(1 << 29, "SetNTFSCompression"),
    flag(1 << 30, "UnsetNTFSCompression"),
    flag(1 << 31, "GacInstall"),
];

const LOCATION_FLAGS: FlagTable = &[
    flag(0x001, "VersionInfoValid"),
    flag(0x002, "VersionInfoNotValid"),
    flag(0x004, "TimeStampInUTC"),
    flag(0x008, "IsUninstallerExe"),
    flag(0x010, "CallInstructionOptimized"),
    flag(0x020, "Touch"),
    flag(0x040, "ChunkEncrypted"),
    flag(0x080, "ChunkCompressed"),
    flag(0x100, "SolidBreak"),
];
const CALL_OPTIMIZED: u16 = 0x010;
const ENCRYPTED: u16 = 0x040;
const COMPRESSED: u16 = 0x080;

/// File location records (5.3.9 and later): slices, chunk, sizes, SHA-1,
/// time, version, flags.
const LOCATION: usize = 74;

/// A file location entry.
#[derive(Clone, Copy, Debug)]
struct Location {
    at: usize,
    first_slice: u32,
    start: u32,
    sub: u64,
    size: u64,
    packed: u64,
    sha1: [u8; 20],
    time: u64,
    version: (u32, u32),
    flags: u16,
}

fn read_location(buf: &[u8], at: usize) -> Option<Location> {
    let sha1: [u8; 20] = buf
        .get(at.checked_add(36)?..at.checked_add(56)?)?
        .try_into()
        .ok()?;
    Some(Location {
        at,
        first_slice: u32_le(buf, at)?,
        start: u32_le(buf, at.checked_add(8)?)?,
        sub: u64_le(buf, at.checked_add(12)?)?,
        size: u64_le(buf, at.checked_add(20)?)?,
        packed: u64_le(buf, at.checked_add(28)?)?,
        sha1,
        time: u64_le(buf, at.checked_add(56)?)?,
        version: (
            u32_le(buf, at.checked_add(64)?)?,
            u32_le(buf, at.checked_add(68)?)?,
        ),
        flags: u16_le(buf, at.checked_add(72)?)?,
    })
}

/// Everything parsed from the setup data.
struct Setup {
    ver: Version,
    unicode: bool,
    /// The decoded header block.
    span: Span,
    data: Vec<u8>,
    header_strings: Vec<(&'static str, Field)>,
    /// Where the counts start.
    counts_at: usize,
    counts: [u32; 16],
    /// The settings after the counts, and whether they have the expected
    /// size.
    settings: (usize, usize),
    settings_expected: bool,
    tables: Vec<Table>,
    /// Where parsing stopped, and why (if it did).
    stopped: Option<(usize, Diagnostic)>,
    /// The decoded location block.
    loc_span: Option<Span>,
    locations: Vec<Location>,
    /// Per chunk (first slice, start offset): the end of its last file in
    /// the decoded chunk, and how many locations it holds.
    chunks: BTreeMap<(u32, u32), (u64, usize)>,
}

impl Setup {
    fn string(&self, name: &str) -> &str {
        self.header_strings
            .iter()
            .find(|(n, _)| *n == name)
            .map_or("", |(_, f)| f.text.as_str())
    }

    /// A setting's offset and size, if the settings were decoded.
    fn setting(&self, name: &str) -> Option<(usize, usize)> {
        if !self.settings_expected {
            return None;
        }
        let mut at = self.settings.0;
        for (n, len) in settings(self.ver) {
            if n == name {
                return Some((at, len));
            }
            at = at.saturating_add(len);
        }
        None
    }

    fn compression(&self) -> Option<u8> {
        let (at, _) = self.setting("CompressMethod")?;
        self.data.get(at).copied()
    }

    fn sub(&self, at: usize, len: usize) -> Span {
        self.span.sub(to_u64(at), to_u64(len))
    }

    fn table(&self, kind: &Kind) -> Option<&Table> {
        self.tables.iter().find(|t| t.kind.name == kind.name)
    }
}

/// Parses the decoded header block (and the location block).
async fn parse(
    cx: &Cx,
    ver: Version,
    unicode: bool,
    span: Span,
    data: Vec<u8>,
    loc: Option<(Span, Vec<u8>)>,
) -> Setup {
    let mut s = Setup {
        ver,
        unicode,
        span,
        data,
        header_strings: Vec::new(),
        counts_at: 0,
        counts: [0; 16],
        settings: (0, 0),
        settings_expected: false,
        tables: Vec::new(),
        stopped: None,
        loc_span: None,
        locations: Vec::new(),
        chunks: BTreeMap::new(),
    };
    if let Some((span, data)) = loc {
        s.loc_span = Some(span);
        let mut at = 0usize;
        let mut n = 0u32;
        while at.saturating_add(LOCATION) <= data.len() {
            n = n.wrapping_add(1);
            if n.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            if let Some(l) = read_location(&data, at) {
                let chunk = s.chunks.entry((l.first_slice, l.start)).or_insert((0, 0));
                chunk.0 = chunk.0.max(l.sub.saturating_add(l.size));
                chunk.1 = chunk.1.saturating_add(1);
                s.locations.push(l);
            }
            at = at.saturating_add(LOCATION);
        }
    }
    if !supported(ver) {
        s.stopped = Some((
            0,
            Diagnostic::unsupported(format!(
                "setup header of Inno Setup {}.{}.{}",
                ver.major, ver.minor, ver.patch
            )),
        ));
        return s;
    }
    let buf = std::mem::take(&mut s.data);
    let mut pos = 0usize;
    let fail = |s: &mut Setup, pos: usize, what: &str| {
        s.stopped = Some((pos, Diagnostic::malformed(format!("cannot parse {what}"))));
    };
    for &(name, since) in HEADER_STRINGS {
        if ver < since {
            continue;
        }
        match read_str(&buf, pos, Wide, unicode) {
            Some((f, next)) => {
                s.header_strings.push((name, f));
                pos = next;
            }
            None => {
                fail(&mut s, pos, name);
                s.data = buf;
                return s;
            }
        }
    }
    for name in HEADER_ANSI {
        match read_str(&buf, pos, Ansi, unicode) {
            Some((f, next)) => {
                s.header_strings.push((name, f));
                pos = next;
            }
            None => {
                fail(&mut s, pos, name);
                s.data = buf;
                return s;
            }
        }
    }
    if !unicode {
        pos = pos.saturating_add(32); // LeadBytes
    }
    s.counts_at = pos;
    for (i, c) in s.counts.iter_mut().enumerate() {
        *c = u32_le(&buf, pos.saturating_add(i.saturating_mul(4))).unwrap_or(0);
    }
    pos = pos.saturating_add(64);
    // The settings: find the size that lets the first entry parse.
    let expected: usize = settings(ver).iter().map(|(_, n)| n).sum();
    let first = TABLES
        .iter()
        .find(|(_, i)| s.counts.get(*i).copied().unwrap_or(0) > 0)
        .map(|(k, _)| *k);
    let found = candidates(expected)
        .chain(candidates(expected.saturating_add(9)))
        .find(|&(t, _)| plausible(&buf, pos.saturating_add(t), first, unicode));
    let Some((len, exact)) = found else {
        fail(&mut s, pos, "the settings");
        s.data = buf;
        return s;
    };
    s.settings = (pos, len);
    s.settings_expected = exact;
    pos = pos.saturating_add(len);
    for (i, &(kind, index)) in TABLES.iter().enumerate() {
        let n = s.counts.get(index).copied().unwrap_or(0);
        if to_usize(n.into()) > buf.len() {
            fail(&mut s, pos, kind.name);
            break;
        }
        // The next record that exists: a later table, or the icons.
        let next = TABLES
            .get(i.saturating_add(1)..)
            .unwrap_or_default()
            .iter()
            .find(|(_, j)| s.counts.get(*j).copied().unwrap_or(0) > 0)
            .map(|(k, _)| *k)
            .or_else(|| (s.counts.get(ICON_COUNT).copied().unwrap_or(0) > 0).then_some(&ICONS));
        match read_table(cx, &buf, pos, n, kind, unicode, next).await {
            Some((t, end)) => {
                s.tables.push(t);
                pos = end;
            }
            None => {
                fail(&mut s, pos, kind.name);
                break;
            }
        }
    }
    if s.stopped.is_none() {
        s.stopped = Some((
            pos,
            Diagnostic::note("icons, INI, registry and run entries are not decoded"),
        ));
    }
    s.data = buf;
    s
}

// ---------------------------------------------------------------------------
// Dissection

/// Where things are: the setup data, the file data, and the input.
#[derive(Clone, Copy, Debug)]
struct Layout {
    input: Input,
    /// The setup data (from the version string on).
    data: Span,
    /// Where the file chunks start (`Offset1`), if known.
    files: Option<Span>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 23)).await?;
    if head == b"Inno Setup Setup Data (" {
        let l = Layout {
            input,
            data: input.span,
            files: None,
        };
        return setup_data(&cx, &l, None).await;
    }
    let table = input.span.sub(0, TABLE);
    let new = head.starts_with(ID_NEW);
    cx.emit(struct_node("Loader table", table, LE, new, table_fields));
    let t = cx.read(table).await?;
    let w =
        |i: usize| u64::from(u32_le(&t, 12usize.saturating_add(i.saturating_mul(4))).unwrap_or(0));
    // The offsets are into setup.exe: the input this table is embedded in.
    let exe = input.outer;
    if exe == input.span {
        cx.annotate("Inno Setup loader table");
        cx.diag(Diagnostic::note(
            "the offsets point into the setup program this table belongs to",
        ));
        return Ok(());
    }
    // 5.1.5+: version, total size, setup.e32 offset, size, CRC, Offset0,
    // Offset1; older: total size, setup.e32 offset, compressed and
    // uncompressed size, CRC, Offset0, Offset1.
    let (exe_at, exe_size, offset0, offset1) = if new {
        (w(2), w(3), w(5), w(6))
    } else {
        (w(1), w(3), w(5), w(6))
    };
    let exe_span = exe.sub(exe_at, offset0.saturating_sub(exe_at));
    cx.emit(
        Node::new("Setup program (setup.e32)")
            .span(exe_span)
            .summary(format!(
                "{}, {} uncompressed",
                size(exe_span.len),
                size(exe_size)
            ))
            .desc("The installer's user interface, compressed; not decoded"),
    );
    let l = Layout {
        input,
        data: exe.tail(offset0),
        files: (offset1 != 0).then(|| exe.tail(offset1)),
    };
    setup_data(&cx, &l, Some(new)).await
}

fn table_fields(f: &mut Fields<'_>, new: &bool) -> Result<()> {
    let block = f.block();
    let crc_ok = block
        .data
        .get(..40)
        .map(|b| crc32(b) == u32_le(&block.data, 40).unwrap_or(0));
    f.bytes("ID", 12).emit()?;
    if *new {
        f.u32("Version").emit()?;
        f.u32("Total size").emit()?;
        f.u32("Setup program offset").hex().emit()?;
        f.u32("Setup program size").desc("Uncompressed").emit()?;
        f.u32("Setup program CRC-32")
            .hex()
            .desc("Uncompressed")
            .emit()?;
    } else {
        f.u32("Total size").emit()?;
        f.u32("Setup program offset").hex().emit()?;
        f.u32("Setup program compressed size").emit()?;
        f.u32("Setup program size").desc("Uncompressed").emit()?;
        f.u32("Setup program checksum").hex().emit()?;
    }
    f.u32("Offset0").hex().desc("Setup data").emit()?;
    f.u32("Offset1")
        .hex()
        .desc("File data (0 with disk spanning)")
        .emit()?;
    f.u32("Table CRC-32")
        .hex()
        .with(|_, n| match crc_ok {
            Some(true) => n.summary("valid"),
            Some(false) => n.diag(Diagnostic::warning("CRC mismatch")),
            None => n,
        })
        .emit()?;
    Ok(())
}

/// Emits the setup data and what it holds; `table` says whether a loader
/// table came first (and which kind).
async fn setup_data(cx: &Cx, l: &Layout, table: Option<bool>) -> Result<()> {
    let data = l.data;
    let vs = cx.read_avail(data.sub(0, VERSION_LEN)).await?;
    let version = crate::text::until_nul(&vs);
    cx.emit(
        Node::new("Version")
            .span(data.sub(0, VERSION_LEN))
            .value(text(version.clone())),
    );
    let Some((ver, unicode)) = parse_version(&version) else {
        cx.annotate("Inno Setup installer");
        return Err(Diagnostic::malformed("not an Inno Setup version string").at(data.sub(0, 64)));
    };
    let mut summary = format!(
        "Inno Setup {}.{}.{}{}",
        ver.major,
        ver.minor,
        ver.patch,
        if unicode { " (Unicode)" } else { "" }
    );
    if table.is_none() {
        summary.push_str(" setup data");
    }
    let setup = match setup(cx, l, ver, unicode).await {
        Ok(s) => s,
        Err(e) => {
            cx.annotate(summary);
            return Err(e);
        }
    };
    let app = setup.string("AppName");
    if !app.is_empty() {
        summary.push_str(&format!(", {app}"));
        let version = setup.string("AppVersion");
        if !version.is_empty() {
            summary.push_str(&format!(" {version}"));
        }
    }
    if let Some(c) = setup
        .compression()
        .and_then(|c| lookup(COMPRESSION, c.into()))
    {
        summary.push_str(&format!(", {c}"));
    }
    let files = setup.table(&FILES).map_or(0, |t| t.entries.len());
    summary.push_str(&format!(", {}", count(to_u64(files), "file", "files")));
    cx.annotate(summary);
    emit_blocks(cx, l, &setup).await;
    Ok(())
}

/// The parsed setup data, decoded once.
async fn setup(cx: &Cx, l: &Layout, ver: Version, unicode: bool) -> Result<Arc<Setup>> {
    if let Some(s) = cx.cached::<Setup>(l.data, "inno setup") {
        return Ok(s);
    }
    let first = block(cx, l.data, VERSION_LEN, ver).await?;
    let header = first.decoded.clone()?;
    let data = read_all(cx, header).await?;
    let second_at = VERSION_LEN.saturating_add(9).saturating_add(first.stored);
    let loc = match block(cx, l.data, second_at, ver).await {
        Ok(b) => match b.decoded {
            Ok(span) => Some((span, read_all(cx, span).await?)),
            Err(_) => None,
        },
        Err(_) => None,
    };
    let s = Arc::new(parse(cx, ver, unicode, header, data, loc).await);
    cx.cache(l.data, "inno setup", s.clone());
    Ok(s)
}

async fn emit_blocks(cx: &Cx, l: &Layout, s: &Arc<Setup>) {
    let ver = s.ver;
    let mut at = VERSION_LEN;
    for name in ["Header block", "File location block"] {
        match block(cx, l.data, at, ver).await {
            Ok(b) => {
                let mut node = Node::new(name)
                    .span(b.span)
                    .summary(format!(
                        "{}, {}",
                        size(b.stored),
                        if b.compressed { "compressed" } else { "stored" }
                    ))
                    .lazy(block_fields, (l.input, l.data, at, ver));
                if let Some(e) = b.problem {
                    node = node.diag(e);
                }
                if let Err(e) = b.decoded {
                    node = node.diag(e);
                }
                cx.emit(node);
                at = at.saturating_add(9).saturating_add(b.stored);
            }
            Err(e) => {
                cx.emit(Node::new(name).span(l.data.tail(at)).diag(e));
                break;
            }
        }
    }
    let state = (*l, s.ver, s.unicode);
    cx.emit(
        Node::new("Setup header")
            .span(s.sub(0, s.settings.0.saturating_add(s.settings.1)))
            .summary(format!(
                "{} {}",
                s.string("AppName"),
                s.string("AppVersion")
            ))
            .lazy(header_fields, state),
    );
    for t in &s.tables {
        if t.entries.is_empty() {
            continue;
        }
        let start = t.entries.first().map_or(0, |e| e.start);
        let end = t.entries.last().map_or(0, |e| e.end);
        let mut node = Node::new(t.kind.name)
            .span(s.sub(start, end.saturating_sub(start)))
            .summary(count(to_u64(t.entries.len()), t.kind.one, t.kind.many))
            .lazy(entries, (*l, s.ver, s.unicode, t.kind.name));
        if !t.expected {
            node = node.diag(Diagnostic::note(
                "fixed fields of an unexpected size; shown raw",
            ));
        }
        cx.emit(node);
    }
    if let Some((pos, e)) = &s.stopped {
        cx.emit(
            Node::new("Remaining entries")
                .span(s.span.tail(to_u64(*pos)))
                .diag(e.clone()),
        );
    }
    if let Some(span) = s.loc_span {
        cx.emit(
            Node::new("File locations")
                .span(span)
                .summary(count(to_u64(s.locations.len()), "location", "locations"))
                .lazy(locations, state),
        );
    }
    let files = s.table(&FILES).map_or(0, |t| t.entries.len());
    if files > 0 {
        cx.emit(
            Node::new("Files")
                .summary(count(to_u64(files), "file", "files"))
                .lazy(self::files, state),
        );
    }
    if let Some(data) = l.files {
        cx.emit(Node::new("Chunks").span(data).lazy(chunks, state));
    }
}

/// Expanders find the parsed data again through the cache.
async fn again(cx: &Cx, l: &Layout, ver: Version, unicode: bool) -> Result<Arc<Setup>> {
    setup(cx, l, ver, unicode).await
}

async fn block_fields(cx: Cx, (input, data, at, ver): (Input, Span, u64, Version)) -> Result<()> {
    let b = block(&cx, data, at, ver).await?;
    cx.emit(struct_node(
        "Block header",
        data.sub(at, 9),
        LE,
        (),
        |f, _| {
            f.u32("CRC-32").hex().desc("Of the next 9 bytes").emit()?;
            f.u32("Stored size").emit()?;
            f.u8("Compressed").emit()?;
            Ok(())
        },
    ));
    let region = data.sub(at.saturating_add(9), b.stored);
    let n = b.stored.div_ceil(CHUNK.saturating_add(4));
    cx.emit(
        Node::new("Chunks")
            .span(region)
            .summary(count(n, "chunk", "chunks"))
            .lazy(block_chunks, region),
    );
    match b.decoded {
        Ok(span) => cx.emit(
            Node::new("Decompressed")
                .span(span)
                .summary(size(span.len))
                .lazy(raw_data, input.nested(span)),
        ),
        Err(e) => cx.emit(Node::new("Decompressed").diag(e)),
    }
    Ok(())
}

async fn raw_data(cx: Cx, input: Input) -> Result<()> {
    cx.emit(Node::new("Data").span(input.span));
    Ok(())
}

/// The 4 KiB chunks of a compressed block, with their CRCs checked.
async fn block_chunks(cx: Cx, region: Span) -> Result<()> {
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    while pos < region.len {
        let here = pos;
        cx.mark(move || here);
        let crc = cx.read(region.sub(pos, 4)).await?;
        let body = region.sub(pos.saturating_add(4), CHUNK);
        let bytes = cx.read_avail(body).await?;
        let stored = u32_le(&crc, 0).unwrap_or(0);
        let mut node = Node::new(format!("Chunk at {pos:#x}"))
            .span(region.sub(pos, body.len.saturating_add(4)))
            .value(hex(stored.into()));
        node = if crc32(&bytes) == stored {
            node.summary(format!("{}, CRC valid", size(body.len)))
        } else {
            node.diag(Diagnostic::warning("chunk CRC mismatch"))
        };
        cx.push(node).await;
        pos = pos.saturating_add(4).saturating_add(CHUNK);
    }
    Ok(())
}

fn str_node(s: &Setup, name: &'static str, f: &Field) -> Node {
    let node = Node::new(name).span(s.sub(f.at, f.len.saturating_add(4)));
    if name == "CompiledCodeText" || name == "Data" {
        node.summary(size(to_u64(f.len)))
    } else {
        node.value(text(f.text.clone()))
    }
}

async fn header_fields(cx: Cx, (l, ver, unicode): (Layout, Version, bool)) -> Result<()> {
    let s = again(&cx, &l, ver, unicode).await?;
    for (name, f) in &s.header_strings {
        cx.emit(str_node(&s, name, f));
    }
    if !s.unicode && s.counts_at >= 32 {
        cx.emit(Node::new("LeadBytes").span(s.sub(s.counts_at.saturating_sub(32), 32)));
    }
    let counts: Vec<Node> = COUNTS
        .iter()
        .zip(s.counts)
        .enumerate()
        .map(|(i, (name, c))| {
            Node::new(*name)
                .span(s.sub(s.counts_at.saturating_add(i.saturating_mul(4)), 4))
                .value(uint(c.into()))
        })
        .collect();
    cx.emit(
        Node::new("Counts")
            .span(s.sub(s.counts_at, 64))
            .lazy(emit_nodes, Arc::new(counts)),
    );
    let (at, len) = s.settings;
    let span = s.sub(at, len);
    if !s.settings_expected {
        cx.emit(Node::new("Settings").span(span).diag(Diagnostic::note(
            "not the size we expect for this version; shown raw",
        )));
        return Ok(());
    }
    let mut fields = Vec::new();
    let mut p = at;
    for (name, n) in settings(s.ver) {
        let n = if name == "Options" {
            at.saturating_add(len).saturating_sub(p)
        } else {
            n
        };
        let bytes = s.data.get(p..p.saturating_add(n)).unwrap_or_default();
        let node = Node::new(name).span(s.sub(p, n));
        let le = |b: &[u8]| b.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x));
        fields.push(match (name, n) {
            ("CompressMethod", _) => node.value(Value::Enum {
                raw: le(bytes),
                bits: 8,
                name: lookup(COMPRESSION, le(bytes)),
            }),
            ("PrivilegesRequired", _) => node.value(Value::Enum {
                raw: le(bytes),
                bits: 8,
                name: lookup(PRIVILEGES, le(bytes)),
            }),
            ("DisableDirPage" | "DisableProgramGroupPage", _) => node.value(Value::Enum {
                raw: le(bytes),
                bits: 8,
                name: lookup(YES_NO_AUTO, le(bytes)),
            }),
            ("MinVersion" | "OnlyBelowVersion", _) => node.summary(winver(bytes)),
            ("BackColor" | "BackColor2" | "WizardImageBackColor", _) => node.value(hex(le(bytes))),
            (_, 1 | 4 | 8) => node.value(uint(le(bytes))),
            _ => node.value(Value::Bytes(bytes.to_vec())),
        });
        p = p.saturating_add(n);
    }
    cx.emit(
        Node::new("Settings")
            .span(span)
            .lazy(emit_nodes, Arc::new(fields)),
    );
    Ok(())
}

/// A `TSetupVersionData`: Windows version (build, minor, major), NT
/// version, NT service pack (minor, major).
fn winver(b: &[u8]) -> String {
    let ver = |o: usize| {
        let build = u16_le(b, o).unwrap_or(0);
        let minor = b.get(o.saturating_add(2)).copied().unwrap_or(0);
        let major = b.get(o.saturating_add(3)).copied().unwrap_or(0);
        format!("{major}.{minor}.{build}")
    };
    let sp_minor = b.get(8).copied().unwrap_or(0);
    let sp_major = b.get(9).copied().unwrap_or(0);
    format!("Windows {}, NT {} SP {sp_major}.{sp_minor}", ver(0), ver(4))
}

async fn entries(
    cx: Cx,
    (l, ver, unicode, name): (Layout, Version, bool, &'static str),
) -> Result<()> {
    let s = again(&cx, &l, ver, unicode).await?;
    let Some(t) = s.tables.iter().find(|t| t.kind.name == name) else {
        return Ok(());
    };
    cx.set_count(Count::Exact(to_u64(t.entries.len())));
    let first = cx.resume::<usize>().unwrap_or(0);
    for (i, e) in t.entries.iter().enumerate().skip(first) {
        cx.mark(move || i);
        let mut fields: Vec<Node> = t
            .kind
            .strings
            .iter()
            .zip(&e.strings)
            .map(|((n, _), f)| str_node(&s, n, f))
            .collect();
        let tail = s.sub(e.tail, e.end.saturating_sub(e.tail));
        if t.kind.name == FILES.name && t.expected {
            fields.extend(file_fields(&s, e));
        } else {
            fields.push(Node::new("Fixed fields").span(tail));
        }
        let label = e
            .strings
            .get(usize::from(t.kind.name == FILES.name))
            .map(|f| f.text.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("{} {i}", t.kind.one));
        cx.push(
            Node::new(label)
                .span(s.sub(e.start, e.end.saturating_sub(e.start)))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

/// The fixed fields of a file entry.
fn file_fields(s: &Setup, e: &Entry) -> Vec<Node> {
    let t = e.tail;
    let d = &s.data;
    let at = |o: usize| t.saturating_add(o);
    let b = d.get(t..e.end).unwrap_or_default();
    let location = u32_le(d, at(20)).unwrap_or(u32::MAX);
    vec![
        Node::new("MinVersion")
            .span(s.sub(t, 10))
            .summary(winver(b)),
        Node::new("OnlyBelowVersion")
            .span(s.sub(at(10), 10))
            .summary(winver(b.get(10..).unwrap_or_default())),
        Node::new("LocationEntry")
            .span(s.sub(at(20), 4))
            .value(Value::Int {
                value: i64::from(location as i32),
                bits: 32,
            }),
        Node::new("Attributes")
            .span(s.sub(at(24), 4))
            .value(hex(u32_le(d, at(24)).unwrap_or(0).into())),
        Node::new("ExternalSize")
            .span(s.sub(at(28), 8))
            .value(uint(u64_le(d, at(28)).unwrap_or(0))),
        Node::new("PermissionsEntry")
            .span(s.sub(at(36), 2))
            .value(Value::Int {
                value: i64::from(u16_le(d, at(36)).unwrap_or(0) as i16),
                bits: 16,
            }),
        Node::new("Options")
            .span(s.sub(at(38), 4))
            .value(crate::formats::util::lines::flags(
                FILE_FLAGS,
                u32_le(d, at(38)).unwrap_or(0).into(),
                32,
            )),
        Node::new("FileType")
            .span(s.sub(at(42), 1))
            .value(Value::Enum {
                raw: d.get(at(42)).copied().unwrap_or(0).into(),
                bits: 8,
                name: lookup(
                    &[(0, "UserFile"), (1, "UninstExe")],
                    d.get(at(42)).copied().unwrap_or(0).into(),
                ),
            }),
    ]
}

fn location_fields(s: &Setup, loc: &Location) -> Vec<Node> {
    let Some(span) = s.loc_span else {
        return Vec::new();
    };
    let at = |o: usize| span.sub(to_u64(loc.at.saturating_add(o)), 0);
    let f = |o: usize, n: u64| Span::new(span.source, at(o).offset, n);
    let mut out = vec![
        Node::new("FirstSlice")
            .span(f(0, 4))
            .value(uint(loc.first_slice.into())),
        Node::new("StartOffset")
            .span(f(8, 4))
            .value(hex(loc.start.into()))
            .desc("Of the chunk, from Offset1"),
        Node::new("ChunkSubOffset")
            .span(f(12, 8))
            .value(hex(loc.sub)),
        Node::new("OriginalSize")
            .span(f(20, 8))
            .value(uint(loc.size))
            .summary(size(loc.size)),
        Node::new("ChunkCompressedSize")
            .span(f(28, 8))
            .value(uint(loc.packed)),
        Node::new("SHA-1")
            .span(f(36, 20))
            .value(Value::Bytes(loc.sha1.to_vec())),
    ];
    if let Some(t) = filetime("TimeStamp", loc.time) {
        out.push(t.span(f(56, 8)));
    }
    out.push(Node::new("FileVersion").span(f(64, 8)).value(text(format!(
        "{}.{}.{}.{}",
        loc.version.0 >> 16,
        loc.version.0 & 0xffff,
        loc.version.1 >> 16,
        loc.version.1 & 0xffff
    ))));
    out.push(
        Node::new("Flags")
            .span(f(72, 2))
            .value(crate::formats::util::lines::flags(
                LOCATION_FLAGS,
                loc.flags.into(),
                16,
            )),
    );
    out
}

async fn locations(cx: Cx, (l, ver, unicode): (Layout, Version, bool)) -> Result<()> {
    let s = again(&cx, &l, ver, unicode).await?;
    cx.set_count(Count::Exact(to_u64(s.locations.len())));
    let first = cx.resume::<usize>().unwrap_or(0);
    for (i, loc) in s.locations.iter().enumerate().skip(first) {
        cx.mark(move || i);
        let span = s.loc_span.map_or(l.data.sub(0, 0), |sp| {
            sp.sub(to_u64(loc.at), to_u64(LOCATION))
        });
        cx.push(
            Node::new(format!("Location {i}"))
                .span(span)
                .summary(format!("{}, chunk at {:#x}", size(loc.size), loc.start))
                .lazy(emit_nodes, Arc::new(location_fields(&s, loc))),
        )
        .await;
    }
    Ok(())
}

/// A chunk: where it is in the file data, its codec and decoded size (the
/// furthest any file in it reaches).
#[derive(Clone, Debug)]
struct ChunkInfo {
    span: Span,
    codec: Option<Codec>,
    why: String,
    total: u64,
}

fn chunk_info(s: &Setup, files: Span, loc: &Location) -> ChunkInfo {
    let total = s
        .chunks
        .get(&(loc.first_slice, loc.start))
        .map_or(0, |&(end, _)| end);
    let span = files.sub(u64::from(loc.start).saturating_add(4), loc.packed);
    let (codec, why) = if loc.flags & ENCRYPTED != 0 {
        (None, "encrypted".to_owned())
    } else if loc.flags & COMPRESSED == 0 {
        (Some(Codec::Stored), "stored".to_owned())
    } else {
        match s.compression() {
            Some(1) => (Some(Codec::Zlib), "zlib".to_owned()),
            Some(2) => (Some(Codec::Bzip2), "bzip2".to_owned()),
            Some(3) => (None, "LZMA".to_owned()),
            Some(4) => (None, "LZMA2".to_owned()),
            Some(c) => (None, format!("compression method {c}")),
            None => (None, "unknown compression".to_owned()),
        }
    };
    ChunkInfo {
        span,
        codec,
        why,
        total,
    }
}

/// The codec of a chunk's data, reading LZMA properties where needed.
async fn chunk_codec(cx: &Cx, c: &ChunkInfo) -> Result<(Codec, Span)> {
    if let Some(codec) = &c.codec {
        return Ok((codec.clone(), c.span));
    }
    match c.why.as_str() {
        "LZMA" => lzma_codec(cx, c.span).await,
        "LZMA2" => {
            let p = cx.read(c.span.sub(0, 1)).await?;
            let bits = u32::from(p.first().copied().unwrap_or(0));
            let dict = (bits <= 40).then(|| {
                let base = 2u32 | (bits & 1);
                base.checked_shl((bits >> 1).saturating_add(11))
                    .unwrap_or(u32::MAX)
            });
            Ok((Codec::Lzma2 { dict }, c.span.tail(1)))
        }
        why => Err(Diagnostic::unsupported(why.to_owned())),
    }
}

async fn files(cx: Cx, (l, ver, unicode): (Layout, Version, bool)) -> Result<()> {
    let s = again(&cx, &l, ver, unicode).await?;
    let Some(t) = s.table(&FILES) else {
        return Ok(());
    };
    cx.set_count(Count::Exact(to_u64(t.entries.len())));
    let first = cx.resume::<usize>().unwrap_or(0);
    for (i, e) in t.entries.iter().enumerate().skip(first) {
        cx.mark(move || i);
        let dest = e.strings.get(1).map(|f| f.text.clone()).unwrap_or_default();
        let source = e
            .strings
            .first()
            .map(|f| f.text.clone())
            .unwrap_or_default();
        let mut children = vec![
            Node::new("Entry")
                .value(uint(to_u64(i)))
                .target(s.sub(e.start, e.end.saturating_sub(e.start))),
            Node::new("Source").value(text(source)),
        ];
        let location = if t.expected {
            u32_le(&s.data, e.tail.saturating_add(20))
        } else {
            None
        };
        let loc = location.and_then(|n| s.locations.get(to_usize(n.into())));
        let mut node = Node::new(if dest.is_empty() {
            format!("file {i}")
        } else {
            dest
        });
        match loc {
            Some(loc) => {
                node = node.summary(size(loc.size));
                children.extend(location_fields(&s, loc));
                children.push(content_node(&l, &s, loc));
            }
            None => {
                node = node.summary(match location {
                    Some(u32::MAX) => "no data (external or uninstaller)".to_owned(),
                    Some(n) => format!("location {n} missing"),
                    None => "location not decoded".to_owned(),
                });
            }
        }
        cx.push(node.lazy(emit_nodes, Arc::new(children))).await;
    }
    Ok(())
}

fn content_node(l: &Layout, s: &Setup, loc: &Location) -> Node {
    let Some(files) = l.files else {
        return Node::new("Content").summary("file data not available (setup-0 only)");
    };
    let c = chunk_info(s, files, loc);
    let mut node = Node::new("Content")
        .span(c.span)
        .summary(format!("{} in a {} chunk", size(loc.size), c.why))
        .lazy(
            chunk_part,
            (l.input, c.clone(), loc.sub, loc.size, loc.sha1),
        );
    if loc.flags & ENCRYPTED != 0 {
        node = node.diag(Diagnostic::unsupported("encrypted chunk"));
    }
    if loc.flags & CALL_OPTIMIZED != 0 {
        node = node.diag(Diagnostic::note(
            "x86 call instructions were transformed for compression (not undone)",
        ));
    }
    node
}

/// Files up to this size have their SHA-1 checked when expanded.
const CHECK_LIMIT: u64 = 16 << 20;

async fn chunk_part(
    cx: Cx,
    (input, c, sub, len, sha1): (Input, ChunkInfo, u64, u64, [u8; 20]),
) -> Result<()> {
    let magic = cx
        .read_avail(Span::new(c.span.source, c.span.offset.saturating_sub(4), 4))
        .await?;
    if magic != b"zlb\x1a" {
        cx.diag(Diagnostic::malformed("chunk without its zlb signature"));
    }
    let (codec, data) = chunk_codec(&cx, &c).await?;
    let out = if codec == Codec::Stored {
        data
    } else if c.total > 1 << 20 && c.total <= data.len.saturating_mul(codec.max_ratio()) {
        cx.decode_lazy(data, &codec, c.total)?
    } else {
        let d = decode_span(&cx, data, &codec, Some(c.total)).await?;
        if let Some(e) = d.error {
            cx.diag(e);
        }
        d.span
    };
    let file = out.sub(sub, len);
    if len <= CHECK_LIMIT {
        let bytes = read_all(&cx, file).await?;
        if crate::formats::util::datakit::sha1_paced(&cx, &bytes).await == sha1 {
            cx.emit(Node::new("SHA-1 check").span(file).summary("valid"));
        } else {
            cx.diag(Diagnostic::warning("SHA-1 mismatch"));
        }
    }
    dissect_or_data(cx, input.nested(file)).await
}

async fn chunks(cx: Cx, (l, ver, unicode): (Layout, Version, bool)) -> Result<()> {
    let s = again(&cx, &l, ver, unicode).await?;
    let Some(files) = l.files else {
        return Ok(());
    };
    let mut seen: BTreeSet<(u32, u32)> = BTreeSet::new();
    for loc in &s.locations {
        cx.checkpoint().await;
        let key = (loc.first_slice, loc.start);
        if !seen.insert(key) {
            continue;
        }
        let c = chunk_info(&s, files, loc);
        let whole = files.sub(loc.start.into(), loc.packed.saturating_add(4));
        let n = s.chunks.get(&key).map_or(0, |&(_, n)| n);
        cx.push(
            Node::new(format!("Chunk at {:#x}", loc.start))
                .span(whole)
                .summary(format!(
                    "{}, {} → {}, {}",
                    c.why,
                    size(loc.packed),
                    size(c.total),
                    count(to_u64(n), "file", "files")
                )),
        )
        .await;
    }
    Ok(())
}
