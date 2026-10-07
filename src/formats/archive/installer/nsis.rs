//! NSIS installer data: the overlay of a `setup.exe` built by makensis
//! (NSIS 2.x and 3.x, ANSI and Unicode).
//!
//! A 28-byte *first header* (flags, `0xDEADBEEF`, `NullsoftInst`, the size
//! of the script header and the length of all the data, which includes the
//! first header and the CRC) is followed either by
//!
//! - **non-solid** data: the script header as one block, then the data
//!   blocks; each block is a 32-bit length (high bit: compressed) and its
//!   bytes, compressed on its own; or
//! - **solid** data: one compressed stream holding the same blocks (their
//!   lengths without the flag).
//!
//! Compression is raw DEFLATE, LZMA (5 property bytes, then the raw stream;
//! a solid stream may be preceded by a BCJ filter flag) or NSIS's bzip2
//! variant ([`crate::codec::Codec::NsisBzip2`]). Unless the `NO_CRC` flag
//! is set, a CRC-32 ends the data (it covers the setup program before the
//! data too, so it is shown, not checked).
//!
//! The script header starts with flags and eight (offset, count) pairs
//! locating its blocks: pages, sections, entries, the string table,
//! language tables, control colours, the background font and data. Settings
//! follow whose layout depends on compile-time options; they are shown when
//! the pages start where a default build puts them (0x12c). Entries are
//! seven 32-bit words (an opcode and six parameters); `File` entries
//! (opcode 20) name the output file and point into the data blocks, and
//! `SetOutPath` (opcode 11 with its second parameter set) gives their
//! directory. Strings are byte offsets (in characters) into the string
//! table, or negative language-string indices. Codes mark language
//! strings, shell folders, variables and literal characters (NSIS 3: 1-4,
//! NSIS 2: 255-252), followed by two bytes (one UTF-16 unit in Unicode
//! installers) of 7 bits each.
//!
//! There is no public specification: this is from memory of NSIS's
//! `fileform.h` and of 7-Zip's NSIS reader. Opcode names follow the default
//! build; from opcode 58 on, Unicode builds of NSIS 3 number two extra file
//! opcodes, which we account for, and only names up to `WriteUninstaller`
//! are given. Our fixtures (synthetic, makensis is not available here) are
//! listed and decompiled by 7-Zip with the same file names, paths and
//! contents.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::codec::lzma::Props;
use crate::codec::{Codec, decode_span, read_all};
use crate::cx::{Block, Cx};
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{count, emit_nodes, hex, text, uint};
use crate::formats::{Head, Input, Probe, dissect_or_data, expand_content};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

use super::{filetime, size};

const LE: Endian = Endian::Little;
/// The first header's size.
const FIRST: u64 = 28;
/// The compressed flag of a block length.
const HIGH: u32 = 0x8000_0000;
/// Characters we decode of one string at most.
const MAX_STRING: usize = 4096;
/// Where a default build's script header puts its first block (the pages).
const DEFAULT_HEADER: u64 = 0x12c;
/// Bytes per entry: an opcode and six parameters.
const ENTRY: u64 = 28;
/// The `File` opcode (EW_EXTRACTFILE) and `CreateDirectory`/`SetOutPath`.
const EW_EXTRACTFILE: u32 = 20;
const EW_CREATEDIR: u32 = 11;

fn probe(h: &Head<'_>) -> bool {
    h.at(4, b"\xef\xbe\xad\xdeNullsoftInst")
}

declare_format!(pub FORMAT = "nsis", "NSIS installer data", ["exe"], "application/x-nsis",
    Probe::Custom(probe), dissect);

const FIRST_FLAGS: FlagTable = &[
    flag(1, "UNINSTALL"),
    flag(2, "SILENT"),
    flag(4, "NO_CRC"),
    flag(8, "FORCE_CRC"),
];
const NO_CRC: u32 = 4;

const HEADER_FLAGS: FlagTable = &[
    flag(0x001, "DETAILS_SHOWDETAILS"),
    flag(0x002, "DETAILS_NEVERSHOW"),
    flag(0x004, "PROGRESS_COLORED"),
    flag(0x008, "SILENT"),
    flag(0x010, "SILENT_LOG"),
    flag(0x020, "AUTO_CLOSE"),
    flag(0x040, "DIR_NO_SHOW"),
    flag(0x080, "NO_ROOT_DIR"),
    flag(0x100, "COMP_ONLY_ON_CUSTOM"),
    flag(0x200, "NO_CUSTOM"),
];

const BLOCKS: [&str; 8] = [
    "Pages",
    "Sections",
    "Entries",
    "Strings",
    "Language tables",
    "Control colors",
    "Background font",
    "Data",
];
const NB_PAGES: usize = 0;
const NB_SECTIONS: usize = 1;
const NB_ENTRIES: usize = 2;
const NB_STRINGS: usize = 3;
const NB_LANGTABLES: usize = 4;

const SECTION_FLAGS: FlagTable = &[
    flag(0x001, "SELECTED"),
    flag(0x002, "SECGRP"),
    flag(0x004, "SECGRPEND"),
    flag(0x008, "BOLD"),
    flag(0x010, "RO"),
    flag(0x020, "EXPAND"),
    flag(0x040, "PSELECTED"),
    flag(0x080, "TOGGLED"),
    flag(0x100, "NAMECHG"),
];

const PAGE_KINDS: EnumTable = &[
    (0, "License"),
    (1, "Components"),
    (2, "Directory"),
    (3, "Install files"),
    (4, "Uninstall confirmation"),
    (5, "Completed"),
    (6, "Custom"),
];

const OVERWRITE: EnumTable = &[
    (0, "on"),
    (1, "off"),
    (2, "try"),
    (3, "ifnewer"),
    (4, "ifdiff"),
];

/// Opcodes of a default build and their parameters: `s` a string, `i` a
/// number, `j` a jump (entry index + 1), `v` a variable, `-` a number left
/// out of the summary; parameters past the kinds given are numbers too.
const OPCODES: &[(&str, &str)] = &[
    ("Invalid", ""),
    ("Return", ""),
    ("Nop/Goto", "j"),
    ("Abort", "s"),
    ("Quit", ""),
    ("Call", "j"),
    ("DetailPrint", "s"),
    ("Sleep", "s"),
    ("BringToFront", ""),
    ("SetDetailsView", ""),
    ("SetFileAttributes", "si"),
    ("CreateDirectory", "s"),
    ("IfFileExists", "sjj"),
    ("SetFlag", ""),
    ("IfFlag", ""),
    ("GetFlag", ""),
    ("Rename", "ssi"),
    ("GetFullPathName", "vs"),
    ("SearchPath", "vs"),
    ("GetTempFileName", "vs"),
    ("File", "-s"),
    ("Delete", "si"),
    ("MessageBox", "is"),
    ("RMDir", "si"),
    ("StrLen", "vs"),
    ("StrCpy", "vsss"),
    ("StrCmp", "ssjji"),
    ("ReadEnvStr", "vsi"),
    ("IntCmp", "ssjjj"),
    ("IntOp", "vssi"),
    ("IntFmt", "vss"),
    ("Push/Pop/Exch", ""),
    ("FindWindow", ""),
    ("SendMessage", ""),
    ("IsWindow", ""),
    ("GetDlgItem", ""),
    ("SetCtlColors", ""),
    ("LoadAndSetImage", ""),
    ("CreateFont", ""),
    ("ShowWindow", ""),
    ("ExecShell", "sssi"),
    ("Exec", "si"),
    ("GetFileTime", ""),
    ("GetDLLVersion", ""),
    ("RegDLL", ""),
    ("CreateShortcut", "ssssi"),
    ("CopyFiles", "ssi"),
    ("Reboot", ""),
    ("WriteINIStr", "ssss"),
    ("ReadINIStr", "vsss"),
    ("DeleteReg", ""),
    ("WriteReg", ""),
    ("ReadReg", ""),
    ("EnumReg", ""),
    ("FileClose", ""),
    ("FileOpen", ""),
    ("FileWrite", ""),
    ("FileRead", ""),
];
/// Opcodes from 58 on, by build: ANSI, then Unicode (two UTF-16 file
/// opcodes come first).
const TAIL_ANSI: &[&str] = &[
    "FileSeek",
    "FindClose",
    "FindNext",
    "FindFirst",
    "WriteUninstaller",
];
const TAIL_UNICODE: &[&str] = &[
    "FileWriteUTF16LE",
    "FileReadUTF16LE",
    "FileSeek",
    "FindClose",
    "FindNext",
    "FindFirst",
    "WriteUninstaller",
];

/// NSIS's built-in variables after `$0`-`$9` and `$R0`-`$R9`.
const VARIABLES: [&str; 12] = [
    "CMDLINE",
    "INSTDIR",
    "OUTDIR",
    "EXEDIR",
    "LANGUAGE",
    "TEMP",
    "PLUGINSDIR",
    "EXEPATH",
    "EXEFILE",
    "HWNDPARENT",
    "_CLICK",
    "_OUTDIR",
];

/// Shell folders by CSIDL, as NSIS names them.
const SHELL_FOLDERS: EnumTable = &[
    (0x00, "DESKTOP"),
    (0x02, "SMPROGRAMS"),
    (0x05, "DOCUMENTS"),
    (0x06, "FAVORITES"),
    (0x07, "SMSTARTUP"),
    (0x08, "RECENT"),
    (0x09, "SENDTO"),
    (0x0b, "STARTMENU"),
    (0x0d, "MUSIC"),
    (0x0e, "VIDEOS"),
    (0x10, "DESKTOP"),
    (0x13, "NETHOOD"),
    (0x14, "FONTS"),
    (0x15, "TEMPLATES"),
    (0x16, "STARTMENU"),
    (0x17, "SMPROGRAMS"),
    (0x18, "SMSTARTUP"),
    (0x19, "DESKTOP"),
    (0x1a, "APPDATA"),
    (0x1b, "PRINTHOOD"),
    (0x1c, "LOCALAPPDATA"),
    (0x20, "INTERNET_CACHE"),
    (0x21, "COOKIES"),
    (0x22, "HISTORY"),
    (0x23, "APPDATA"),
    (0x24, "WINDIR"),
    (0x25, "SYSDIR"),
    (0x26, "PROGRAMFILES"),
    (0x27, "PICTURES"),
    (0x28, "PROFILE"),
    (0x2b, "COMMONFILES"),
    (0x2e, "DOCUMENTS"),
    (0x2f, "ADMINTOOLS"),
    (0x30, "ADMINTOOLS"),
    (0x35, "MUSIC"),
    (0x36, "PICTURES"),
    (0x37, "VIDEOS"),
    (0x38, "RESOURCES"),
    (0x39, "RESOURCES_LOCALIZED"),
    (0x3b, "CDBURN_AREA"),
];

// ---------------------------------------------------------------------------
// Layout

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    /// A non-solid installer whose header block is not compressed.
    Stored,
    Deflate,
    Lzma,
    Bzip2,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Stored => "uncompressed header",
            Method::Deflate => "zlib (DEFLATE)",
            Method::Lzma => "LZMA",
            Method::Bzip2 => "bzip2",
        }
    }
}

/// 7-Zip's test for an NSIS LZMA stream: the usual properties (lc=3,
/// lp=0, pb=2), a dictionary size in 64 KiB units, and the range coder's
/// first bytes.
fn is_lzma(p: &[u8]) -> bool {
    matches!(p, [0x5d, 0, 0, _, _, 0, b, ..] if b & 0x80 == 0)
}

/// NSIS bzip2: the block marker, then the top byte of a 24-bit origin
/// pointer below 900 000.
fn is_bzip2(p: &[u8]) -> bool {
    matches!(p, [0x31, b, ..] if *b < 14)
}

/// What the first header and the bytes after it say.
#[derive(Clone, Copy, Debug)]
struct Layout {
    file: Span,
    flags: u32,
    header_size: u32,
    method: Method,
    solid: bool,
    /// A solid LZMA stream's filter flag byte, if it has one.
    filter: Option<u8>,
    /// The end of the blocks (where the CRC starts, if there is one).
    end: u64,
    crc: bool,
}

impl Layout {
    /// A solid stream's compressed bytes (after the filter flag).
    fn solid_span(&self) -> Span {
        let start = FIRST.saturating_add(u64::from(self.filter.is_some()));
        self.file.sub(start, self.end.saturating_sub(start))
    }
}

async fn layout(cx: &Cx, file: Span) -> Result<Layout> {
    let head = cx.read(file.sub(0, FIRST)).await?;
    let flags = u32_le(&head, 0).unwrap_or(0);
    let header_size = u32_le(&head, 20).unwrap_or(0);
    let length = u32_le(&head, 24).unwrap_or(0);
    let sig = cx.read_avail(file.sub(FIRST, 16)).await?;
    let rest = sig.get(4..).unwrap_or_default();
    let (method, solid, filter) = if is_lzma(&sig) {
        (Method::Lzma, true, None)
    } else if let Some(&flag @ (0 | 1)) = sig.first()
        && is_lzma(sig.get(1..).unwrap_or_default())
    {
        (Method::Lzma, true, Some(flag))
    } else {
        let v = u32_le(&sig, 0).unwrap_or(0);
        if v & HIGH != 0 {
            let method = if is_lzma(rest) {
                Method::Lzma
            } else if is_bzip2(rest) {
                Method::Bzip2
            } else {
                Method::Deflate
            };
            (method, false, None)
        } else if v == header_size {
            (Method::Stored, false, None)
        } else if is_bzip2(&sig) {
            (Method::Bzip2, true, None)
        } else {
            (Method::Deflate, true, None)
        }
    };
    let crc = flags & NO_CRC == 0;
    let total = u64::from(length).min(file.len);
    let end = if crc { total.saturating_sub(4) } else { total };
    Ok(Layout {
        file,
        flags,
        header_size,
        method,
        solid,
        filter,
        end,
        crc,
    })
}

/// The codec of a compressed span (a block, or the solid stream), and the
/// span it applies to: LZMA's properties come first.
async fn codec_of(cx: &Cx, span: Span) -> Result<(Codec, Span)> {
    let head = cx.read_avail(span.sub(0, 8)).await?;
    if is_lzma(&head) || (!is_bzip2(&head) && looks_like_props(&head)) {
        let props = Props::from_byte(head.first().copied().unwrap_or(0))?;
        let dict = u32_le(&head, 1).unwrap_or(0);
        return Ok((
            Codec::LzmaRaw {
                props,
                size: None,
                dict: Some(dict),
            },
            span.tail(5),
        ));
    }
    if is_bzip2(&head) {
        return Ok((Codec::NsisBzip2, span));
    }
    Ok((Codec::Deflate, span))
}

/// Properties other than the default ones, with a power-of-two dictionary
/// and the range coder's zero first byte.
fn looks_like_props(p: &[u8]) -> bool {
    let dict = u32_le(p, 1).unwrap_or(0);
    p.first().is_some_and(|&b| b < 9 * 5 * 5)
        && p.get(5) == Some(&0)
        && dict.is_power_of_two()
        && dict >= 1 << 12
}

/// The solid stream's codec (its filter, if any, is not supported).
async fn solid_stream(cx: &Cx, l: &Layout) -> Result<Span> {
    if l.filter == Some(1) {
        return Err(Diagnostic::unsupported("LZMA with the x86 BCJ filter"));
    }
    let span = l.solid_span();
    let (codec, data) = match l.method {
        Method::Lzma => codec_of(cx, span).await?,
        Method::Bzip2 => (Codec::NsisBzip2, span),
        _ => (Codec::Deflate, span),
    };
    // The decoded size is not recorded: allow what the codec can produce;
    // reads past the real end come back short.
    let bound = data.len.saturating_mul(codec.max_ratio()).clamp(1, 1 << 40);
    cx.decode_lazy(data, &codec, bound)
}

// ---------------------------------------------------------------------------
// The script header

/// The decoded script header and where the data blocks are.
struct Script {
    span: Span,
    data: Vec<u8>,
    blocks: [(u64, u64); 8],
    unicode: bool,
    /// ANSI strings with NSIS 2's codes (252-255).
    nsis2: bool,
    /// The data blocks.
    region: Span,
    /// A problem decoding the header (the header may still be usable).
    problem: Option<Diagnostic>,
}

impl Script {
    fn word(&self, at: u64) -> u32 {
        u32_le(&self.data, to_usize(at)).unwrap_or(0)
    }

    fn block(&self, i: usize) -> (u64, u64) {
        self.blocks.get(i).copied().unwrap_or((0, 0))
    }

    /// Where block `i` ends: at the next block that starts after it, or
    /// at the end of the header.
    fn block_end(&self, i: usize) -> u64 {
        let (start, _) = self.block(i);
        self.blocks
            .iter()
            .map(|&(o, _)| o)
            .filter(|&o| o > start)
            .min()
            .unwrap_or(to_u64(self.data.len()))
            .min(to_u64(self.data.len()))
    }

    /// The stride of the records of block `i`.
    fn stride(&self, i: usize) -> u64 {
        let (start, n) = self.block(i);
        if n == 0 {
            return 0;
        }
        self.block_end(i)
            .saturating_sub(start)
            .checked_div(n)
            .unwrap_or(0)
    }

    fn char_size(&self) -> u64 {
        if self.unicode { 2 } else { 1 }
    }

    fn opcode_name(&self, op: u32) -> Option<&'static str> {
        let i = to_usize(op.into());
        if let Some((name, _)) = OPCODES.get(i) {
            return Some(name);
        }
        let tail = if self.unicode {
            TAIL_UNICODE
        } else {
            TAIL_ANSI
        };
        tail.get(i.checked_sub(OPCODES.len())?).copied()
    }

    fn kinds(&self, op: u32) -> &'static str {
        OPCODES.get(to_usize(op.into())).map_or("", |(_, k)| k)
    }

    /// The string a parameter refers to: an offset into the string table,
    /// or a negative language-string index.
    fn string(&self, param: u32) -> String {
        if param & HIGH != 0 {
            return format!("$(LSTR_{})", !param);
        }
        self.decode(u64::from(param), 0)
    }

    /// Decodes the string at character offset `at` of the string table.
    fn decode(&self, at: u64, depth: u8) -> String {
        let (start, _) = self.block(NB_STRINGS);
        let end = to_usize(self.block_end(NB_STRINGS));
        let table = self.data.get(to_usize(start)..end).unwrap_or_default();
        let mut out = String::new();
        let mut pos = to_usize(at.saturating_mul(self.char_size()));
        // Reads a character: a UTF-16 unit or a byte.
        let next = |pos: &mut usize| -> Option<u16> {
            if self.unicode {
                let c = u16_le(table, *pos)?;
                *pos = pos.saturating_add(2);
                Some(c)
            } else {
                let c = table.get(*pos).copied()?;
                *pos = pos.saturating_add(1);
                Some(c.into())
            }
        };
        let (skip, var, shell, lang) = if self.nsis2 {
            (252, 253, 254, 255)
        } else {
            (4, 3, 2, 1)
        };
        let mut units: Vec<u16> = Vec::new();
        let mut bytes: Vec<u8> = Vec::new();
        let flush = |units: &mut Vec<u16>, bytes: &mut Vec<u8>, out: &mut String| {
            if !units.is_empty() {
                out.push_str(&String::from_utf16_lossy(units));
                units.clear();
            }
            if !bytes.is_empty() {
                out.push_str(&crate::text::latin1(bytes));
                bytes.clear();
            }
        };
        for _ in 0..MAX_STRING {
            let Some(c) = next(&mut pos) else { break };
            if c == 0 {
                break;
            }
            if c == skip {
                let Some(lit) = next(&mut pos) else { break };
                if self.unicode {
                    units.push(lit);
                } else {
                    bytes.push(u8::try_from(lit).unwrap_or(b'?'));
                }
                continue;
            }
            if c != var && c != shell && c != lang {
                if self.unicode {
                    units.push(c);
                } else {
                    bytes.push(u8::try_from(c).unwrap_or(b'?'));
                }
                continue;
            }
            // A code with a parameter: two bytes (in one UTF-16 unit in
            // Unicode installers), seven bits each for a number.
            let (lo, hi) = if self.unicode {
                let Some(p) = next(&mut pos) else { break };
                let [lo, hi] = p.to_le_bytes();
                (lo, hi)
            } else {
                let (Some(lo), Some(hi)) = (next(&mut pos), next(&mut pos)) else {
                    break;
                };
                (u8::try_from(lo).unwrap_or(0), u8::try_from(hi).unwrap_or(0))
            };
            let (b0, b1, param) = (lo, hi, u16::from(lo & 0x7f) | u16::from(hi & 0x7f) << 7);
            flush(&mut units, &mut bytes, &mut out);
            if c == var {
                out.push_str(&variable(param));
            } else if c == lang {
                out.push_str(&format!("$(LSTR_{param})"));
            } else {
                out.push_str(&self.shell(b0, b1, depth));
            }
        }
        flush(&mut units, &mut bytes, &mut out);
        out
    }

    /// A shell folder: a CSIDL (for the current user, then for all users),
    /// or with the high bit set a registry value under
    /// `CurrentVersion` named by a string (`$PROGRAMFILES`,
    /// `$COMMONFILES`; bit 6: the 64-bit view).
    fn shell(&self, b0: u8, b1: u8, depth: u8) -> String {
        if b0 & 0x80 != 0 {
            let name = if depth == 0 {
                self.decode(u64::from(b0 & 0x3f), 1)
            } else {
                String::new()
            };
            let suffix = if b0 & 0x40 != 0 { "64" } else { "" };
            return match name.as_str() {
                "ProgramFilesDir" => format!("$PROGRAMFILES{suffix}"),
                "CommonFilesDir" => format!("$COMMONFILES{suffix}"),
                _ => format!("$[{name}]"),
            };
        }
        match lookup(SHELL_FOLDERS, b0.into()).or_else(|| lookup(SHELL_FOLDERS, b1.into())) {
            Some(name) => format!("${name}"),
            None => format!("$[shell {b0:#04x} {b1:#04x}]"),
        }
    }
}

fn variable(i: u16) -> String {
    match i {
        0..=9 => format!("${i}"),
        10..=19 => format!("$R{}", i.saturating_sub(10)),
        _ => match VARIABLES.get(usize::from(i.saturating_sub(20))) {
            Some(name) => format!("${name}"),
            None => format!("$_{i}_"),
        },
    }
}

/// The script header, decoded once per installer.
async fn script(cx: &Cx, l: &Layout) -> Result<Arc<Script>> {
    if let Some(s) = cx.cached::<Script>(l.file, "nsis script") {
        return Ok(s);
    }
    let mut problem = None;
    let (header, region) = if l.solid {
        let stream = solid_stream(cx, l).await?;
        let len = cx.read(stream.sub(0, 4)).await?;
        let size = u64::from(u32_le(&len, 0).unwrap_or(0) & !HIGH);
        let start = 4u64.saturating_add(size);
        (stream.sub(4, size), stream.tail(start))
    } else {
        let len = cx.read(l.file.sub(FIRST, 4)).await?;
        let v = u32_le(&len, 0).unwrap_or(0);
        let packed = l.file.sub(FIRST.saturating_add(4), u64::from(v & !HIGH));
        let start = packed
            .offset
            .saturating_sub(l.file.offset)
            .saturating_add(packed.len);
        let region = l.file.sub(start, l.end.saturating_sub(start));
        if v & HIGH == 0 {
            (packed, region)
        } else {
            let (codec, data) = codec_of(cx, packed).await?;
            let decoded = decode_span(cx, data, &codec, Some(l.header_size.into())).await?;
            problem = decoded.error;
            (decoded.span, region)
        }
    };
    let data = read_all(cx, header).await?;
    if data.len() < 4 + 8 * 8 {
        return Err(Diagnostic::malformed("script header too short").at(header));
    }
    let mut blocks = [(0u64, 0u64); 8];
    for (i, b) in blocks.iter_mut().enumerate() {
        let at = i.saturating_mul(8).saturating_add(4);
        *b = (
            u32_le(&data, at).unwrap_or(0).into(),
            u32_le(&data, at.saturating_add(4)).unwrap_or(0).into(),
        );
    }
    let mut s = Script {
        span: header,
        data,
        blocks,
        unicode: false,
        nsis2: false,
        region,
        problem,
    };
    let start = to_usize(s.block(NB_STRINGS).0);
    let end = to_usize(s.block_end(NB_STRINGS));
    // The string table starts with an empty string: one NUL byte, or two
    // in Unicode installers (ANSI ones continue with a non-empty string).
    s.unicode = u16_le(&s.data, start) == Some(0);
    let table = s.data.get(start..end).unwrap_or_default();
    s.nsis2 =
        !s.unicode && !table.iter().any(|b| (1..=4).contains(b)) && table.iter().any(|&b| b >= 252);
    let s = Arc::new(s);
    cx.cache(l.file, "nsis script", s.clone());
    Ok(s)
}

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(struct_node(
        "First header",
        file.sub(0, FIRST),
        LE,
        (),
        first_header,
    ));
    let l = layout(&cx, file).await?;
    if l.solid {
        let mut node = Node::new("Solid stream")
            .span(l.solid_span())
            .summary(format!("{}, {}", l.method.name(), size(l.solid_span().len)));
        if let Some(flag) = l.filter {
            node = node.desc(format!("After a filter flag byte ({flag})"));
        }
        cx.emit(node);
    } else {
        let len = cx.read_avail(file.sub(FIRST, 4)).await?;
        let v = u32_le(&len, 0).unwrap_or(0);
        cx.emit(
            Node::new("Header block")
                .span(file.sub(FIRST, u64::from(v & !HIGH).saturating_add(4)))
                .summary(format!(
                    "{}, {}",
                    size((v & !HIGH).into()),
                    if v & HIGH != 0 {
                        "compressed"
                    } else {
                        "stored"
                    }
                )),
        );
    }
    let mut summary = format!(
        "NSIS installer, {}{}",
        if l.solid { "solid " } else { "" },
        l.method.name()
    );
    match script(&cx, &l).await {
        Ok(s) => {
            summary.push_str(if s.unicode { ", Unicode" } else { ", ANSI" });
            emit_script(&cx, input, &l, &s, &mut summary);
        }
        Err(e) => cx.emit(Node::new("Script header").diag(e)),
    }
    if l.crc {
        let crc = cx.read_avail(file.sub(l.end, 4)).await?;
        cx.emit(
            Node::new("CRC-32")
                .span(file.sub(l.end, 4))
                .value(hex(u32_le(&crc, 0).unwrap_or(0).into()))
                .desc("Of the setup program and the data before it (not checked)"),
        );
    }
    if l.flags & 1 != 0 {
        summary.push_str(", uninstaller");
    }
    cx.annotate(summary);
    Ok(())
}

fn first_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Flags").flags(FIRST_FLAGS).emit()?;
    f.u32("Signature").hex().emit()?;
    f.ascii("Magic", 12).emit()?;
    f.u32("Script header size")
        .desc("Uncompressed")
        .with(|&v, n| n.summary(size(v.into())))
        .emit()?;
    f.u32("Data length")
        .desc("Of everything from the first header to the CRC, inclusive")
        .with(|&v, n| n.summary(size(v.into())))
        .emit()?;
    Ok(())
}

fn emit_script(cx: &Cx, input: Input, l: &Layout, s: &Arc<Script>, summary: &mut String) {
    let header = Node::new("Script header")
        .span(s.span)
        .summary(size(s.span.len))
        .lazy(header_fields, (*l, s.problem.clone()));
    cx.emit(match &s.problem {
        Some(e) => header.diag(e.clone()),
        None => header,
    });
    let group = |i: usize, what: (&str, &str)| {
        let (start, n) = s.block(i);
        Node::new(BLOCKS.get(i).copied().unwrap_or("Block"))
            .span(s.span.sub(start, s.block_end(i).saturating_sub(start)))
            .summary(count(n, what.0, what.1))
    };
    let state = (input, *l);
    cx.emit(group(NB_PAGES, ("page", "pages")).lazy(pages, state));
    cx.emit(group(NB_SECTIONS, ("section", "sections")).lazy(sections, state));
    cx.emit(group(NB_ENTRIES, ("entry", "entries")).lazy(entries, state));
    let (start, _) = s.block(NB_STRINGS);
    let len = s.block_end(NB_STRINGS).saturating_sub(start);
    cx.emit(
        Node::new("Strings")
            .span(s.span.sub(start, len))
            .summary(size(len))
            .lazy(strings, (input, *l)),
    );
    cx.emit(
        group(NB_LANGTABLES, ("language table", "language tables")).lazy(language_tables, state),
    );
    let files = files_of(s);
    cx.emit(
        Node::new("Files")
            .summary(count(to_u64(files.len()), "file", "files"))
            .lazy(self::files, (input, *l)),
    );
    // A solid stream's decoded length is not known.
    let blocks = Node::new("Data blocks").lazy(data_blocks, (input, *l));
    cx.emit(if l.solid {
        blocks
    } else {
        blocks.span(s.region)
    });
    let (_, sections) = s.block(NB_SECTIONS);
    summary.push_str(&format!(
        ", {}, {}",
        count(to_u64(files.len()), "file", "files"),
        count(sections, "section", "sections")
    ));
}

async fn header_fields(cx: Cx, (l, _problem): (Layout, Option<Diagnostic>)) -> Result<()> {
    let s = script(&cx, &l).await?;
    let block = Block {
        span: s.span,
        data: s.data.clone(),
    };
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Flags").flags(HEADER_FLAGS).emit()?;
    for name in BLOCKS {
        let at = f.peek_span(8);
        let offset = f.u32("Offset").get()?;
        let n = f.u32("Count").get()?;
        cx.emit(
            Node::new(name)
                .span(at)
                .summary(format!("{n} at {offset:#x}")),
        );
    }
    if s.block(NB_PAGES).0 != DEFAULT_HEADER {
        cx.emit(
            Node::new("Settings")
                .span(s.span.sub(0x44, s.block(NB_PAGES).0.saturating_sub(0x44)))
                .diag(Diagnostic::note(
                    "not a default build's layout; settings not decoded",
                )),
        );
        return Ok(());
    }
    let st = |f: &mut Fields<'_>, name: &'static str| -> Result<()> {
        let v = f.u32(name).get()?;
        let at = f.peek_span(0);
        let span = Span::new(at.source, at.offset.saturating_sub(4), 4);
        cx.emit(
            Node::new(name)
                .span(span)
                .value(text(s.string(v)))
                .summary(string_ref(v)),
        );
        Ok(())
    };
    f.u32("Registry root key")
        .hex()
        .desc("Of InstallDirRegKey")
        .emit()?;
    st(&mut f, "Registry key")?;
    st(&mut f, "Registry value")?;
    f.u32("Background color 1").hex().emit()?;
    f.u32("Background color 2").hex().emit()?;
    f.u32("Background text color").hex().emit()?;
    f.u32("Details background color").hex().emit()?;
    f.u32("Details text color").hex().emit()?;
    f.u32("Language table size").emit()?;
    f.u32("License background color").hex().emit()?;
    for name in [
        ".onInit",
        ".onInstSuccess",
        ".onInstFailed",
        ".onUserAbort",
        ".onGUIInit",
        ".onGUIEnd",
        ".onMouseOverSection",
        ".onVerifyInstDir",
        ".onSelChange",
        ".onRebootFailed",
    ] {
        f.u32(name)
            .with(|&v, n| {
                if v == u32::MAX {
                    n.summary("none")
                } else {
                    n.summary(format!("entry #{v}"))
                }
            })
            .emit()?;
    }
    let types = f.peek_span(33 * 4);
    let mut names = Vec::new();
    for i in 0..33u32 {
        let v = f.u32("Install type").get()?;
        if v != 0 {
            names.push(
                Node::new(format!("Install type {i}"))
                    .span(types.sub(u64::from(i).saturating_mul(4), 4))
                    .value(text(s.string(v))),
            );
        }
    }
    cx.emit(
        Node::new("Install types")
            .span(types)
            .summary(count(to_u64(names.len()), "type", "types"))
            .lazy(emit_nodes, Arc::new(names)),
    );
    st(&mut f, "Install directory")?;
    st(&mut f, "Install directory auto-append")?;
    st(&mut f, "Uninstaller child")?;
    st(&mut f, "Uninstaller command")?;
    st(&mut f, "wininit.ini")?;
    Ok(())
}

fn string_ref(v: u32) -> String {
    if v & HIGH != 0 {
        format!("language string {}", !v)
    } else {
        format!("string at {v:#x}")
    }
}

async fn pages(cx: Cx, (_input, l): (Input, Layout)) -> Result<()> {
    let s = script(&cx, &l).await?;
    let (start, n) = s.block(NB_PAGES);
    let stride = s.stride(NB_PAGES);
    if n > 0 && stride < 64 {
        return Err(Diagnostic::malformed(format!("pages of {stride} bytes")));
    }
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = start.saturating_add(i.saturating_mul(stride));
        let w = |k: u64| s.word(at.saturating_add(k.saturating_mul(4)));
        let kind = w(1);
        let name = lookup(PAGE_KINDS, kind.into()).unwrap_or("Page");
        let mut fields = vec![
            Node::new("Dialog ID").value(uint(w(0).into())),
            Node::new("Kind").value(Value::Enum {
                raw: kind.into(),
                bits: 32,
                name: lookup(PAGE_KINDS, kind.into()),
            }),
        ];
        for (k, func) in [
            (2, "Pre function"),
            (3, "Show function"),
            (4, "Leave function"),
        ] {
            let v = w(k);
            fields.push(Node::new(func).value(Value::Int {
                value: i64::from(v as i32),
                bits: 32,
            }));
        }
        fields.push(Node::new("Flags").value(hex(w(5).into())));
        for (k, label) in [
            (6, "Caption"),
            (7, "Back"),
            (8, "Next"),
            (9, "Click next"),
            (10, "Cancel"),
        ] {
            let v = w(k);
            fields.push(
                Node::new(label)
                    .value(text(s.string(v)))
                    .summary(string_ref(v)),
            );
        }
        let span = s.span.sub(at, stride);
        let fields: Vec<Node> = fields
            .into_iter()
            .enumerate()
            .map(|(k, n)| n.span(span.sub(to_u64(k).saturating_mul(4), 4)))
            .collect();
        cx.push(
            Node::new(format!("Page {i}"))
                .span(span)
                .summary(name)
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

async fn sections(cx: Cx, (_input, l): (Input, Layout)) -> Result<()> {
    let s = script(&cx, &l).await?;
    let (start, n) = s.block(NB_SECTIONS);
    let stride = s.stride(NB_SECTIONS);
    if n > 0 && stride < 24 {
        return Err(Diagnostic::malformed(format!("sections of {stride} bytes")));
    }
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = start.saturating_add(i.saturating_mul(stride));
        let span = s.span.sub(at, stride);
        let w = |k: u64| s.word(at.saturating_add(k.saturating_mul(4)));
        let name_ptr = w(0);
        let name = if name_ptr == 0 {
            String::new()
        } else {
            s.string(name_ptr)
        };
        let flags = w(2);
        let code = w(3);
        let code_size = w(4);
        let kb = w(5);
        let f = |k: u64| span.sub(k.saturating_mul(4), 4);
        let fields = vec![
            Node::new("Name")
                .span(f(0))
                .value(text(name.clone()))
                .summary(string_ref(name_ptr)),
            Node::new("Install types")
                .span(f(1))
                .value(hex(w(1).into())),
            Node::new("Flags")
                .span(f(2))
                .value(crate::formats::util::lines::flags(
                    SECTION_FLAGS,
                    flags.into(),
                    32,
                )),
            Node::new("Code")
                .span(f(3))
                .summary(format!("entry #{code}"))
                .value(uint(code.into())),
            Node::new("Code size")
                .span(f(4))
                .value(uint(code_size.into())),
            Node::new("Size (KiB)").span(f(5)).value(uint(kb.into())),
            Node::new("Name buffer").span(span.tail(24)),
        ];
        let label = if name.is_empty() {
            format!("Section {i}")
        } else {
            format!("Section {i}: {name}")
        };
        cx.push(
            Node::new(label)
                .span(span)
                .summary(format!(
                    "entries #{code}–#{}, {kb} KiB",
                    code.saturating_add(code_size).saturating_sub(1)
                ))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

/// An entry's opcode and parameters.
fn entry(s: &Script, i: u64) -> (u32, [u32; 6]) {
    let at = s
        .block(NB_ENTRIES)
        .0
        .saturating_add(i.saturating_mul(ENTRY));
    let mut p = [0u32; 6];
    for (k, slot) in p.iter_mut().enumerate() {
        *slot = s.word(at.saturating_add(to_u64(k).saturating_add(1).saturating_mul(4)));
    }
    (s.word(at), p)
}

/// The number of entries the entries block really holds.
fn entry_count(s: &Script) -> u64 {
    let (start, n) = s.block(NB_ENTRIES);
    n.min(to_u64(s.data.len()).saturating_sub(start) / ENTRY)
}

/// One-line rendering of an entry: its name and its decoded parameters.
fn describe(s: &Script, op: u32, p: &[u32; 6]) -> String {
    let name = s.opcode_name(op).unwrap_or("?");
    let name = match (op, p.get(1)) {
        (EW_CREATEDIR, Some(&v)) if v != 0 => "SetOutPath",
        _ => name,
    };
    let args: Vec<String> = s
        .kinds(op)
        .chars()
        .zip(p.iter())
        .filter(|&(k, _)| k != '-')
        .map(|(k, &v)| param(s, k, v))
        .collect();
    if args.is_empty() {
        name.to_owned()
    } else {
        format!("{name} {}", args.join(", "))
    }
}

fn param(s: &Script, kind: char, v: u32) -> String {
    match kind {
        's' => format!("\"{}\"", s.string(v)),
        'v' => variable(u16::try_from(v).unwrap_or(u16::MAX)),
        'j' if v == 0 => "-".to_owned(),
        'j' => format!("→ #{}", v.saturating_sub(1)),
        _ => format!("{}", v as i32),
    }
}

async fn entries(cx: Cx, (_input, l): (Input, Layout)) -> Result<()> {
    let s = script(&cx, &l).await?;
    let n = entry_count(&s);
    cx.set_count(Count::Exact(n));
    let first = cx.resume::<u64>().unwrap_or(0);
    let start = s.block(NB_ENTRIES).0;
    for i in first..n {
        cx.mark(move || i);
        let (op, p) = entry(&s, i);
        let span = s
            .span
            .sub(start.saturating_add(i.saturating_mul(ENTRY)), ENTRY);
        let kinds: Vec<char> = s.kinds(op).chars().collect();
        let mut fields = vec![Node::new("Opcode").span(span.sub(0, 4)).value(Value::Enum {
            raw: op.into(),
            bits: 32,
            name: s.opcode_name(op),
        })];
        for (k, &v) in p.iter().enumerate() {
            let at = span.sub(to_u64(k).saturating_add(1).saturating_mul(4), 4);
            let node = Node::new(format!("Parameter {k}")).span(at);
            fields.push(match kinds.get(k) {
                Some('s') => node.value(text(s.string(v))).summary(string_ref(v)),
                Some(&kind @ ('v' | 'j')) => node.value(hex(v.into())).summary(param(&s, kind, v)),
                _ => node.value(Value::Int {
                    value: i64::from(v as i32),
                    bits: 32,
                }),
            });
        }
        cx.push(
            Node::new(format!("#{i}"))
                .span(span)
                .summary(describe(&s, op, &p))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

async fn strings(cx: Cx, (_input, l): (Input, Layout)) -> Result<()> {
    let s = script(&cx, &l).await?;
    let (start, _) = s.block(NB_STRINGS);
    let end = s.block_end(NB_STRINGS);
    let unit = s.char_size();
    let mut pos = cx.resume::<u64>().unwrap_or(start);
    while pos < end {
        let here = pos;
        cx.mark(move || here);
        // Find the terminator.
        let mut stop = pos;
        while stop < end {
            let c = if s.unicode {
                u16_le(&s.data, to_usize(stop)).unwrap_or(0)
            } else {
                s.data.get(to_usize(stop)).copied().unwrap_or(0).into()
            };
            stop = stop.saturating_add(unit);
            if c == 0 {
                break;
            }
        }
        let offset = pos.saturating_sub(start).checked_div(unit).unwrap_or(0);
        cx.push(
            Node::new(format!("@{offset:#x}"))
                .span(s.span.sub(pos, stop.saturating_sub(pos)))
                .value(text(s.decode(offset, 0))),
        )
        .await;
        pos = stop.max(pos.saturating_add(unit));
    }
    Ok(())
}

async fn language_tables(cx: Cx, (_input, l): (Input, Layout)) -> Result<()> {
    let s = script(&cx, &l).await?;
    let (start, n) = s.block(NB_LANGTABLES);
    let stride = s.stride(NB_LANGTABLES);
    if n > 0 && stride < 10 {
        return Err(Diagnostic::malformed(format!(
            "language tables of {stride} bytes"
        )));
    }
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = start.saturating_add(i.saturating_mul(stride));
        let span = s.span.sub(at, stride);
        let id = u16_le(&s.data, to_usize(at)).unwrap_or(0);
        let strings = stride.saturating_sub(10) / 4;
        let mut fields = vec![
            Node::new("Language ID")
                .span(span.sub(0, 2))
                .value(hex(id.into()))
                .summary(crate::formats::util::lcid::describe(id.into())),
            Node::new("Dialog offset")
                .span(span.sub(2, 4))
                .value(hex(s.word(at.saturating_add(2)).into())),
            Node::new("Right to left")
                .span(span.sub(6, 4))
                .value(uint(s.word(at.saturating_add(6)).into())),
        ];
        let mut list = Vec::new();
        for k in 0..strings.min(4096) {
            let off = at.saturating_add(10).saturating_add(k.saturating_mul(4));
            let v = s.word(off);
            list.push(
                Node::new(format!("LSTR_{k}"))
                    .span(s.span.sub(off, 4))
                    .value(text(s.string(v)))
                    .summary(string_ref(v)),
            );
        }
        fields.push(
            Node::new("Strings")
                .span(span.tail(10))
                .summary(count(strings, "string", "strings"))
                .lazy(emit_nodes, Arc::new(list)),
        );
        cx.push(
            Node::new(format!("Language table {i}"))
                .span(span)
                .summary(crate::formats::util::lcid::describe(id.into()))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

/// A `File` entry: its index, output path and parameters.
struct FileEntry {
    index: u64,
    path: String,
    params: [u32; 6],
}

/// The `File` entries, with their paths joined to the `SetOutPath` before
/// them (in entry order, which is how the script runs them unless it
/// jumps around).
fn files_of(s: &Script) -> Vec<FileEntry> {
    let mut out = Vec::new();
    let mut outdir = String::new();
    for i in 0..entry_count(s) {
        let (op, p) = entry(s, i);
        match op {
            EW_CREATEDIR if p.get(1).is_some_and(|&v| v != 0) => {
                outdir = s.string(p.first().copied().unwrap_or(0));
            }
            EW_EXTRACTFILE => {
                let name = s.string(p.get(1).copied().unwrap_or(0));
                let absolute =
                    name.starts_with('$') || name.starts_with('\\') || name.get(1..2) == Some(":");
                let path = if absolute || outdir.is_empty() {
                    name
                } else {
                    format!("{}\\{name}", outdir.trim_end_matches('\\'))
                };
                out.push(FileEntry {
                    index: i,
                    path,
                    params: p,
                });
            }
            _ => {}
        }
        if out.len() >= 1 << 20 {
            break;
        }
    }
    out
}

async fn files(cx: Cx, (input, l): (Input, Layout)) -> Result<()> {
    let s = script(&cx, &l).await?;
    let list = files_of(&s);
    cx.set_count(Count::Exact(to_u64(list.len())));
    let start = s.block(NB_ENTRIES).0;
    for f in list {
        let [overwrite, _, offset, low, high, _] = f.params;
        let entry_span = s
            .span
            .sub(start.saturating_add(f.index.saturating_mul(ENTRY)), ENTRY);
        let mut children = vec![
            Node::new("Entry").value(uint(f.index)).target(entry_span),
            Node::new("Overwrite").value(Value::Enum {
                raw: overwrite.into(),
                bits: 32,
                name: lookup(OVERWRITE, (overwrite & 7).into()),
            }),
        ];
        children.extend(filetime(
            "Modification time",
            u64::from(high) << 32 | u64::from(low),
        ));
        children.push(
            Node::new("Data block offset")
                .value(hex(offset.into()))
                .target(s.region.sub(offset.into(), 4)),
        );
        let (node, _) = block_node(&cx, input, &l, &s, offset.into(), "Content".to_owned()).await;
        children.push(node.clone());
        let mut file = Node::new(f.path).lazy(emit_nodes, Arc::new(children));
        if let Some(sum) = node.summary {
            file = file.summary(sum);
        }
        if let Some(span) = node.span {
            file = file.span(span);
        }
        cx.push(file).await;
    }
    Ok(())
}

/// A node for the data block at `offset`: its content, decoded on
/// expansion; and the block's total size (length field included), if it
/// could be read.
async fn block_node(
    cx: &Cx,
    input: Input,
    l: &Layout,
    s: &Script,
    offset: u64,
    name: String,
) -> (Node, Option<u64>) {
    let len = match cx
        .read(
            s.region
                .sub_exact(offset, 4)
                .unwrap_or(s.region.sub(offset, 4)),
        )
        .await
    {
        Ok(b) if b.len() == 4 => u32_le(&b, 0).unwrap_or(0),
        Ok(_) => {
            return (
                Node::new(name.clone()).diag(Diagnostic::malformed("data block outside the data")),
                None,
            );
        }
        Err(e) => return (Node::new(name.clone()).diag(e), None),
    };
    let compressed = !l.solid && len & HIGH != 0;
    let size_ = u64::from(if l.solid { len } else { len & !HIGH });
    let body = s.region.sub(offset.saturating_add(4), size_);
    let mut node = if compressed {
        Node::new(name.clone())
            .span(body)
            .summary(format!("{} compressed", size(size_)))
            .lazy(compressed_block, (input, body))
    } else {
        Node::new(name)
            .span(body)
            .summary(size(size_))
            .lazy(stored_block, input.nested(body))
    };
    if body.len < size_ {
        node = node.diag(Diagnostic::truncated(
            Span::new(body.source, body.offset, size_),
            body.len,
        ));
    }
    (node, Some(size_.saturating_add(4)))
}

async fn stored_block(cx: Cx, input: Input) -> Result<()> {
    dissect_or_data(cx, input).await
}

async fn compressed_block(cx: Cx, (input, body): (Input, Span)) -> Result<()> {
    let (codec, data) = codec_of(&cx, body).await?;
    expand_content(cx, (input, data, codec, None)).await
}

async fn data_blocks(cx: Cx, (input, l): (Input, Layout)) -> Result<()> {
    let s = script(&cx, &l).await?;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    // A solid stream's length is not known: stop at its end.
    while pos < s.region.len {
        let at = (pos, index);
        let (node, total) = block_node(&cx, input, &l, &s, pos, format!("Block {index}")).await;
        let Some(total) = total else {
            if !l.solid {
                cx.push(node.summary(format!("at {pos:#x}"))).await;
            }
            break;
        };
        cx.mark(move || at);
        cx.push(node.desc(format!("At {pos:#x} of the data"))).await;
        pos = pos.saturating_add(total);
        index = index.saturating_add(1);
    }
    Ok(())
}
