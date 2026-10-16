//! 7z archives.
//!
//! A 32-byte signature header points at the "next header" at the end of the
//! file. That header is either plain (`kHeader`), describing packed streams,
//! folders (coder chains) and files, or encoded (`kEncodedHeader`): a small
//! streams description of where the real, usually LZMA-compressed, header is
//! packed. Encoded headers are decompressed and then parsed like plain ones.
//!
//! Members of "Copy" folders are dissected in place. Folders whose coders
//! form a simple chain (LZMA, LZMA2, PPMd, Deflate, Deflate64, BZip2,
//! Zstandard or LZ4, then optionally BCJ (x86, ARM, ARM64, ARM Thumb,
//! PowerPC, SPARC, IA-64, RISC-V) or Delta filters) are decoded, and so are
//! BCJ2 folders (four packed streams, see `codec::bcj2`); solid folders are
//! split into their files by the substream sizes.
//!
//! Encrypted folders (an AES-256 coder, 7zAES, in front of the chain) ask
//! for the archive's password when their content is expanded: one realm
//! per archive, so an encrypted header and the files share one prompt.
//! The key derivation (2^19 SHA-256 rounds by default) runs in budgeted
//! steps, and the data is decrypted lazily with the rest of the chain.
//! 7z keeps no password check value, so a password is checked by decoding
//! the start of the folder (and its CRC where it covers that start): a
//! wrong one fails there and the next attempt is asked for. A stored
//! folder (AES and no decompressor, `-mx0`) has nothing to fail, so it is
//! checked on the zeros 7-Zip pads its last block with and on the CRC of
//! its first file (decrypted as far as 64 MiB); with neither, the password
//! is checked on another folder of the archive that can check it (7-Zip
//! encrypts a whole archive with one password), and only an archive with
//! no such folder leaves it encrypted rather than show what a wrong
//! password would. Only a checked key serves the other folders. An
//! encrypted BCJ2 folder has an AES coder in front of each packed stream
//! (one key, an IV each). An encrypted header (`-mhe=on`) is decrypted
//! only when the files, folders or header outline are expanded. The
//! password is hashed as UTF-16LE.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_le, u64_le};
use crate::codec::crypto::{Key, sevenzip};
use crate::codec::lzma::Post;
use crate::codec::{crc32, decode_span, read_all};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{emit_nodes, unsupported};
use crate::formats::util::fmt;
use crate::formats::util::fmt::count;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Codec, Format, Input, Probe, dissect_or_data, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const SIGNATURE_HEADER: u64 = 32;

pub static FORMAT: Format = Format {
    name: "7z",
    title: "7-Zip archive",
    extensions: &["7z"],
    mime: "application/x-7z-compressed",
    probe: Probe::Magic(&[(0, b"7z\xbc\xaf\x27\x1c")]),
    dissect: crate::expander!(dissect: Input),
};

const PROPERTY: EnumTable = &[
    (0x00, "kEnd"),
    (0x01, "kHeader"),
    (0x02, "kArchiveProperties"),
    (0x03, "kAdditionalStreamsInfo"),
    (0x04, "kMainStreamsInfo"),
    (0x05, "kFilesInfo"),
    (0x06, "kPackInfo"),
    (0x07, "kUnPackInfo"),
    (0x08, "kSubStreamsInfo"),
    (0x09, "kSize"),
    (0x0a, "kCRC"),
    (0x0b, "kFolder"),
    (0x0c, "kCodersUnPackSize"),
    (0x0d, "kNumUnPackStream"),
    (0x0e, "kEmptyStream"),
    (0x0f, "kEmptyFile"),
    (0x10, "kAnti"),
    (0x11, "kName"),
    (0x12, "kCTime"),
    (0x13, "kATime"),
    (0x14, "kMTime"),
    (0x15, "kWinAttributes"),
    (0x16, "kComment"),
    (0x17, "kEncodedHeader"),
    (0x18, "kStartPos"),
    (0x19, "kDummy"),
];

/// Coder method IDs (big-endian byte strings, as stored).
fn method_name(id: &[u8]) -> String {
    let name = match id {
        [0x00] => "Copy",
        [0x03] => "Delta",
        [0x04] => "BCJ x86",
        [0x05] => "BCJ PowerPC",
        [0x06] => "BCJ IA-64",
        [0x07] => "BCJ ARM",
        [0x08] => "BCJ ARM-Thumb",
        [0x09] => "BCJ SPARC",
        [0x0a] => "BCJ ARM64",
        [0x0b] => "BCJ RISC-V",
        [0x21] => "LZMA2",
        [0x03, 0x01, 0x01] => "LZMA",
        [0x03, 0x03, 0x01, 0x03] => "BCJ x86",
        [0x03, 0x03, 0x01, 0x1b] => "BCJ2",
        [0x03, 0x03, 0x02, 0x05] => "BCJ PowerPC",
        [0x03, 0x03, 0x04, 0x01] => "BCJ IA-64",
        [0x03, 0x03, 0x05, 0x01] => "BCJ ARM",
        [0x03, 0x03, 0x07, 0x01] => "BCJ ARM-Thumb",
        [0x03, 0x03, 0x08, 0x05] => "BCJ SPARC",
        [0x03, 0x04, 0x01] => "PPMd",
        [0x04, 0x01, 0x08] => "Deflate",
        [0x04, 0x01, 0x09] => "Deflate64",
        [0x04, 0x02, 0x02] => "BZip2",
        [0x04, 0xf7, 0x11, 0x01] => "Zstandard",
        [0x04, 0xf7, 0x11, 0x04] => "LZ4",
        [0x06, 0xf1, 0x07, 0x01] => "AES-256",
        _ => {
            let hex: Vec<String> = id.iter().map(|b| format!("{b:02x}")).collect();
            return format!("method {}", hex.join(""));
        }
    };
    name.to_owned()
}

record! {
    pub struct SignatureHeader {
        signature: bytes[6] "Signature",
        major: u8 "Major version",
        minor: u8 "Minor version",
        start_crc: u32 "Start header CRC" .hex(),
        next_offset: u64 "Next header offset" .hex() .desc("Relative to the end of this header"),
        next_size: u64 "Next header size" .with(|&s, n| n.summary(fmt::size(s))),
        next_crc: u32 "Next header CRC" .hex(),
    }
}

// ---------------------------------------------------------------------------
// Header parser

/// A node under construction: label, byte range in the header, value,
/// summary and children. Turned into lazy [`Node`]s for display.
#[derive(Clone, Debug, Default)]
struct Item {
    name: String,
    start: usize,
    end: usize,
    value: Option<Value>,
    summary: Option<String>,
    children: Arc<Vec<Item>>,
}

#[derive(Clone, Debug, Default)]
struct Coder {
    id: Vec<u8>,
    ins: u64,
    outs: u64,
    props: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct Folder {
    coders: Vec<Coder>,
    /// (input index, output index) pairs connecting coders.
    binds: Vec<(u64, u64)>,
    unpack_sizes: Vec<u64>,
    /// Packed streams this folder reads.
    packed: u64,
    /// The coder input each packed stream feeds (listed when there are
    /// several; else the input no bind pair feeds).
    pack_inputs: Vec<u64>,
    /// The sizes of this folder's packed streams, in order.
    pack_sizes: Vec<u64>,
    /// Files (substreams) in this folder.
    streams: u64,
    /// The CRC-32 of the folder's output, if recorded.
    crc: Option<u32>,
}

impl Folder {
    fn methods(&self) -> String {
        let names: Vec<String> = self.coders.iter().map(|c| method_name(&c.id)).collect();
        names.join(" + ")
    }

    /// The final output size: the output not bound to another coder's input.
    fn unpack_size(&self) -> u64 {
        let last = (0..to_u64(self.unpack_sizes.len()))
            .find(|i| self.binds.iter().all(|&(_, out)| out != *i))
            .unwrap_or(0);
        self.unpack_sizes.get(to_usize(last)).copied().unwrap_or(0)
    }
}

#[derive(Clone, Debug, Default)]
struct Streams {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder>,
    /// Sizes of the substreams of all folders, in order.
    sizes: Vec<u64>,
    /// CRC-32s of the substreams, where recorded (aligned with `sizes`).
    crcs: Vec<Option<u32>>,
}

#[derive(Clone, Debug, Default)]
struct File {
    name: String,
    has_stream: bool,
    is_dir: bool,
    mtime: Option<u64>,
    attributes: Option<u32>,
}

/// The files of an archive, as their properties were read.
#[derive(Clone, Debug, Default)]
struct Files {
    count: u64,
    /// Names of the first files (the rest have none).
    names: Vec<String>,
    /// One per file, if the archive marks empty streams.
    empty_stream: Vec<bool>,
    /// One per empty stream: an empty file rather than a directory.
    empty_file: Vec<bool>,
    mtimes: BTreeMap<u64, u64>,
    attributes: BTreeMap<u64, u32>,
}

impl Files {
    /// The files in order.
    fn iter(&self) -> impl Iterator<Item = File> + '_ {
        let mut empties = 0usize;
        (0..self.count).map(move |i| {
            let at = to_usize(i);
            let empty = self.empty_stream.get(at).copied().unwrap_or(false);
            let attributes = self.attributes.get(&i).copied();
            let mut is_dir = false;
            if empty {
                is_dir = !self.empty_file.get(empties).copied().unwrap_or(false);
                empties = empties.saturating_add(1);
            }
            if attributes.is_some_and(|a| a & 0x10 != 0) {
                is_dir = true;
            }
            File {
                name: self.names.get(at).cloned().unwrap_or_default(),
                has_stream: !empty,
                is_dir,
                mtime: self.mtimes.get(&i).copied(),
                attributes,
            }
        })
    }
}

/// Whether item `i` is defined: all are (`None`), or its bit is set.
fn is_defined(defined: Option<&[bool]>, i: u64) -> bool {
    defined.is_none_or(|d| d.get(to_usize(i)).copied().unwrap_or(false))
}

#[derive(Clone, Debug, Default)]
struct Archive {
    encoded: bool,
    streams: Streams,
    files: Files,
    outline: Vec<Item>,
}

struct Parser<'a> {
    data: &'a [u8],
    at: usize,
    /// Yields to the host in loops over the header's (input-sized) lists.
    cx: &'a Cx,
}

type P<T> = std::result::Result<T, &'static str>;

/// The most coders, and coder inputs or outputs, in one folder.
const MAX_CODERS: u64 = 64;

impl Parser<'_> {
    fn byte(&mut self) -> P<u8> {
        let b = *self.data.get(self.at).ok_or("unexpected end of header")?;
        self.at = self.at.saturating_add(1);
        Ok(b)
    }

    fn bytes(&mut self, n: u64) -> P<&[u8]> {
        let end = self.at.checked_add(to_usize(n)).ok_or("size overflow")?;
        let b = self
            .data
            .get(self.at..end)
            .ok_or("unexpected end of header")?;
        self.at = end;
        Ok(b)
    }

    /// 7z's variable-length NUMBER: leading one bits of the first byte say
    /// how many little-endian bytes follow.
    fn number(&mut self) -> P<u64> {
        let first = self.byte()?;
        let mut value = 0u64;
        let mut mask = 0x80u8;
        for i in 0..8u32 {
            if first & mask == 0 {
                let high = u64::from(first & mask.wrapping_sub(1));
                return Ok(value | high.checked_shl(i.saturating_mul(8)).unwrap_or(0));
            }
            value |= u64::from(self.byte()?)
                .checked_shl(i.saturating_mul(8))
                .unwrap_or(0);
            mask >>= 1;
        }
        Ok(value)
    }

    /// A count that bounds an allocation: at least `min` bytes per item must
    /// remain.
    fn count(&mut self, min: u64) -> P<u64> {
        let n = self.number()?;
        let left = to_u64(self.data.len().saturating_sub(self.at));
        if n.saturating_mul(min.max(1)) > left.saturating_mul(8) {
            return Err("count exceeds the header size");
        }
        Ok(n)
    }

    fn u32(&mut self) -> P<u32> {
        let v = u32_le(self.data, self.at).ok_or("unexpected end of header")?;
        self.at = self.at.saturating_add(4);
        Ok(v)
    }

    fn u64(&mut self) -> P<u64> {
        let v = u64_le(self.data, self.at).ok_or("unexpected end of header")?;
        self.at = self.at.saturating_add(8);
        Ok(v)
    }

    fn bits(&mut self, n: u64) -> P<Vec<bool>> {
        let bytes = self.bytes(n.div_ceil(8))?;
        Ok((0..n)
            .map(|i| {
                bytes
                    .get(to_usize(i / 8))
                    .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
            })
            .collect())
    }

    /// AllAreDefined byte, then a bit vector if not all are (`None` if all
    /// are: nothing to allocate for a count alone).
    fn defined_bits(&mut self, n: u64) -> P<Option<Vec<bool>>> {
        if self.byte()? != 0 {
            Ok(None)
        } else {
            self.bits(n).map(Some)
        }
    }

    /// AllAreDefined byte, then a bit vector if not all are.
    fn defined(&mut self, n: u64) -> P<Vec<bool>> {
        if self.byte()? != 0 {
            Ok((0..n).map(|_| true).collect())
        } else {
            self.bits(n)
        }
    }

    fn item(&self, name: impl Into<String>, start: usize) -> Item {
        Item {
            name: name.into(),
            start,
            end: self.at,
            ..Item::default()
        }
    }

    fn expect(&mut self, id: u8) -> P<()> {
        if self.byte()? == id {
            Ok(())
        } else {
            Err("unexpected property")
        }
    }

    async fn digests(&mut self, n: u64) -> P<(Item, Vec<Option<u32>>)> {
        let start = self.at.saturating_sub(1);
        let defined = self.defined(n)?;
        let mut values = Vec::new();
        for d in &defined {
            self.cx.checkpoint().await;
            values.push(if *d { Some(self.u32()?) } else { None });
        }
        let crcs = defined.iter().filter(|&&d| d).count();
        let item = self
            .item("kCRC", start)
            .with_summary(count(to_u64(crcs), "CRC", "CRCs"));
        Ok((item, values))
    }

    async fn pack_info(&mut self, s: &mut Streams) -> P<Item> {
        let start = self.at.saturating_sub(1);
        s.pack_pos = self.number()?;
        let n = self.count(1)?;
        let mut children = Vec::new();
        loop {
            let at = self.at;
            match self.byte()? {
                0x00 => break,
                0x09 => {
                    for _ in 0..n {
                        self.cx.checkpoint().await;
                        s.pack_sizes.push(self.number()?);
                    }
                    children.push(
                        self.item("kSize", at)
                            .with_summary(count(n, "size", "sizes")),
                    );
                }
                0x0a => children.push(self.digests(n).await?.0),
                _ => return Err("unexpected property in pack info"),
            }
        }
        let mut item = self.item("kPackInfo", start).with_summary(format!(
            "{}, at {:#x}",
            count(n, "packed stream", "packed streams"),
            s.pack_pos
        ));
        item.children = Arc::new(children);
        Ok(item)
    }

    fn folder(&mut self) -> P<Folder> {
        let coders = self.count(2)?;
        // 7-Zip's own limits (k_Scan_NumCoders_MAX, k_Scan_NumCodersStreams_in_Folder_MAX):
        // they also bound the quadratic bind-pair searches over a folder.
        if coders > MAX_CODERS {
            return Err("too many coders in a folder");
        }
        let mut f = Folder::default();
        let mut ins = 0u64;
        let mut outs = 0u64;
        for _ in 0..coders {
            let flags = self.byte()?;
            let id = self.bytes(u64::from(flags & 0x0f))?.to_vec();
            let (i, o) = if flags & 0x10 != 0 {
                (self.number()?, self.number()?)
            } else {
                (1, 1)
            };
            let props = if flags & 0x20 != 0 {
                let size = self.number()?;
                self.bytes(size)?.to_vec()
            } else {
                Vec::new()
            };
            ins = ins.saturating_add(i);
            outs = outs.saturating_add(o);
            f.coders.push(Coder {
                id,
                ins: i,
                outs: o,
                props,
            });
        }
        if ins > MAX_CODERS || outs > MAX_CODERS {
            return Err("too many coder streams in a folder");
        }
        let bind_pairs = outs.saturating_sub(1);
        for _ in 0..bind_pairs {
            let bind = (self.number()?, self.number()?);
            f.binds.push(bind);
        }
        f.packed = ins.saturating_sub(bind_pairs);
        if f.packed > 1 {
            if f.packed > to_u64(self.data.len()) {
                return Err("too many packed streams");
            }
            for _ in 0..f.packed {
                let input = self.number()?;
                f.pack_inputs.push(input);
            }
        } else if let Some(input) = (0..ins).find(|i| f.binds.iter().all(|&(inp, _)| inp != *i)) {
            f.pack_inputs.push(input);
        }
        f.streams = 1;
        Ok(f)
    }

    async fn unpack_info(&mut self, s: &mut Streams) -> P<Item> {
        let start = self.at.saturating_sub(1);
        self.expect(0x0b)?;
        let n = self.count(2)?;
        if self.byte()? != 0 {
            return Err("external folders are not supported");
        }
        let mut children = Vec::new();
        for i in 0..n {
            self.cx.checkpoint().await;
            let at = self.at;
            let f = self.folder()?;
            children.push(
                self.item(format!("Folder {i}"), at)
                    .with_summary(f.methods()),
            );
            s.folders.push(f);
        }
        let at = self.at;
        self.expect(0x0c)?;
        for f in &mut s.folders {
            self.cx.checkpoint().await;
            let outs = f.coders.iter().fold(0u64, |a, c| a.saturating_add(c.outs));
            for _ in 0..outs {
                f.unpack_sizes.push(self.number()?);
            }
        }
        children.push(self.item("kCodersUnPackSize", at));
        loop {
            match self.byte()? {
                0x00 => break,
                0x0a => {
                    let (item, crcs) = self.digests(n).await?;
                    for (f, crc) in s.folders.iter_mut().zip(crcs) {
                        f.crc = crc;
                    }
                    children.push(item);
                }
                _ => return Err("unexpected property in unpack info"),
            }
        }
        let mut item = self
            .item("kUnPackInfo", start)
            .with_summary(count(n, "folder", "folders"));
        item.children = Arc::new(children);
        Ok(item)
    }

    async fn substreams(&mut self, s: &mut Streams) -> P<Item> {
        let start = self.at.saturating_sub(1);
        let mut children = Vec::new();
        let mut kind = self.byte()?;
        if kind == 0x0d {
            let at = self.at.saturating_sub(1);
            for f in &mut s.folders {
                self.cx.checkpoint().await;
                f.streams = self.number()?;
            }
            children.push(self.item("kNumUnPackStream", at));
            kind = self.byte()?;
        }
        let total = s
            .folders
            .iter()
            .fold(0u64, |a, f| a.saturating_add(f.streams));
        if total > to_u64(self.data.len()).saturating_mul(8) {
            return Err("too many substreams");
        }
        let sizes_present = kind == 0x09;
        let at = self.at.saturating_sub(1);
        for f in &s.folders {
            let mut sum = 0u64;
            for i in 0..f.streams {
                self.cx.checkpoint().await;
                let size = if sizes_present && i.saturating_add(1) < f.streams {
                    self.number()?
                } else {
                    f.unpack_size().saturating_sub(sum)
                };
                sum = sum.saturating_add(size);
                s.sizes.push(size);
            }
        }
        if sizes_present {
            children.push(self.item("kSize", at));
            kind = self.byte()?;
        }
        loop {
            match kind {
                0x00 => break,
                0x0a => {
                    // Digests for the streams whose CRC the folder does not
                    // already give (a folder of one stream with a CRC).
                    let known = |f: &Folder| f.streams == 1 && f.crc.is_some();
                    let n = s
                        .folders
                        .iter()
                        .filter(|f| !known(f))
                        .fold(0u64, |a, f| a.saturating_add(f.streams));
                    let (item, crcs) = self.digests(n).await?;
                    let mut crcs = crcs.into_iter();
                    s.crcs.clear();
                    for f in &s.folders {
                        self.cx.checkpoint().await;
                        if known(f) {
                            s.crcs.push(f.crc);
                        } else {
                            for _ in 0..f.streams {
                                s.crcs.push(crcs.next().flatten());
                            }
                        }
                    }
                    children.push(item);
                }
                _ => return Err("unexpected property in substreams info"),
            }
            kind = self.byte()?;
        }
        let mut item = self
            .item("kSubStreamsInfo", start)
            .with_summary(count(total, "stream", "streams"));
        item.children = Arc::new(children);
        Ok(item)
    }

    async fn streams_info(&mut self, s: &mut Streams) -> P<Vec<Item>> {
        let mut items = Vec::new();
        let mut saw_substreams = false;
        loop {
            match self.byte()? {
                0x00 => break,
                0x06 => items.push(self.pack_info(s).await?),
                0x07 => items.push(self.unpack_info(s).await?),
                0x08 => {
                    saw_substreams = true;
                    items.push(self.substreams(s).await?);
                }
                _ => return Err("unexpected property in streams info"),
            }
        }
        // Each folder's packed stream sizes, in order.
        let mut next = 0usize;
        for f in &mut s.folders {
            self.cx.checkpoint().await;
            let n = to_usize(f.packed.min(MAX_CODERS));
            f.pack_sizes = s
                .pack_sizes
                .get(next..next.saturating_add(n))
                .unwrap_or_default()
                .to_vec();
            next = next.saturating_add(n);
        }
        if !saw_substreams {
            for f in &s.folders {
                self.cx.checkpoint().await;
                s.sizes.push(f.unpack_size());
                s.crcs.push(f.crc);
            }
        } else if s.crcs.is_empty() {
            // No substream digests: a folder of one stream may have its own.
            for f in &s.folders {
                self.cx.checkpoint().await;
                for _ in 0..f.streams {
                    s.crcs.push(if f.streams == 1 { f.crc } else { None });
                }
            }
        }
        Ok(items)
    }

    async fn files_info(&mut self, a: &mut Archive) -> P<Item> {
        let start = self.at.saturating_sub(1);
        let n = self.count(1)?;
        // Properties are kept as read (a bit per file at most 8 per byte, a
        // name at least 2 bytes, a time 8); `Files::iter` puts the files
        // together. Nothing is allocated per file for the count alone.
        let mut files = Files {
            count: n,
            ..Files::default()
        };
        let mut children = Vec::new();
        loop {
            self.cx.checkpoint().await;
            let at = self.at;
            let kind = self.byte()?;
            if kind == 0 {
                break;
            }
            let size = self.number()?;
            let body = self.bytes(size)?.to_vec();
            let mut sub = Parser {
                data: &body,
                at: 0,
                cx: self.cx,
            };
            let mut summary = None;
            match kind {
                0x0e => {
                    files.empty_stream = sub.bits(n)?;
                    let empties = files.empty_stream.iter().filter(|&&e| e).count();
                    summary = Some(count(to_u64(empties), "empty stream", "empty streams"));
                }
                0x0f => {
                    let empties = to_u64(files.empty_stream.iter().filter(|&&e| e).count());
                    files.empty_file = sub.bits(empties)?;
                }
                0x11 => {
                    if sub.byte()? != 0 {
                        return Err("external names are not supported");
                    }
                    // Once the data runs out (nothing left to decode), the
                    // remaining names are empty.
                    let mut names = Vec::new();
                    while to_u64(names.len()) < n {
                        let rest = body.get(sub.at..).unwrap_or_default();
                        let (name, len, _) = crate::text::utf16z(rest, Endian::Little);
                        if len == 0 {
                            break;
                        }
                        for _ in 0..len.div_ceil(4096) {
                            self.cx.checkpoint().await;
                        }
                        names.push(name);
                        sub.at = sub.at.saturating_add(len);
                    }
                    files.names = names;
                }
                0x12..=0x14 => {
                    let defined = sub.defined_bits(n)?;
                    if sub.byte()? != 0 {
                        return Err("external times are not supported");
                    }
                    for i in 0..n {
                        self.cx.checkpoint().await;
                        if is_defined(defined.as_deref(), i) {
                            let t = sub.u64()?;
                            if kind == 0x14 {
                                files.mtimes.insert(i, t);
                            }
                        }
                    }
                }
                0x15 => {
                    let defined = sub.defined_bits(n)?;
                    if sub.byte()? != 0 {
                        return Err("external attributes are not supported");
                    }
                    for i in 0..n {
                        self.cx.checkpoint().await;
                        if is_defined(defined.as_deref(), i) {
                            files.attributes.insert(i, sub.u32()?);
                        }
                    }
                }
                _ => {}
            }
            let name = crate::value::lookup(PROPERTY, kind.into())
                .map_or_else(|| format!("Property {kind:#04x}"), str::to_owned);
            let mut item = self.item(name, at);
            item.summary = summary.or_else(|| Some(fmt::size(size)));
            children.push(item);
        }
        a.files = files;
        let mut item = self
            .item("kFilesInfo", start)
            .with_summary(count(n, "file", "files"));
        item.children = Arc::new(children);
        Ok(item)
    }

    async fn header(&mut self) -> P<Archive> {
        let mut a = Archive::default();
        match self.byte()? {
            0x01 => {
                loop {
                    let at = self.at;
                    match self.byte()? {
                        0x00 => break,
                        0x02 => {
                            // Archive properties: (type, size, data) until 0.
                            loop {
                                self.cx.checkpoint().await;
                                let t = self.byte()?;
                                if t == 0 {
                                    break;
                                }
                                let size = self.number()?;
                                self.bytes(size)?;
                            }
                            a.outline.push(self.item("kArchiveProperties", at));
                        }
                        0x03 => {
                            let mut extra = Streams::default();
                            let children = self.streams_info(&mut extra).await?;
                            let mut item = self.item("kAdditionalStreamsInfo", at);
                            item.children = Arc::new(children);
                            a.outline.push(item);
                        }
                        0x04 => {
                            let mut streams = Streams::default();
                            let children = self.streams_info(&mut streams).await?;
                            a.streams = streams;
                            let mut item = self.item("kMainStreamsInfo", at);
                            item.children = Arc::new(children);
                            a.outline.push(item);
                        }
                        0x05 => {
                            let item = self.files_info(&mut a).await?;
                            a.outline.push(item);
                        }
                        _ => return Err("unexpected property in header"),
                    }
                }
            }
            0x17 => {
                a.encoded = true;
                let mut streams = Streams::default();
                let children = self.streams_info(&mut streams).await?;
                a.streams = streams;
                let mut item = self.item("kEncodedHeader", 0);
                item.children = Arc::new(children);
                a.outline.push(item);
            }
            _ => return Err("next header is neither kHeader nor kEncodedHeader"),
        }
        Ok(a)
    }
}

impl Item {
    fn with_summary(mut self, s: impl Into<String>) -> Self {
        self.summary = Some(s.into());
        self
    }

    fn node(&self, base: Span) -> Node {
        let mut node = Node::new(self.name.clone()).span(base.sub(
            to_u64(self.start),
            to_u64(self.end.saturating_sub(self.start)),
        ));
        if let Some(v) = &self.value {
            node = node.value(v.clone());
        }
        if let Some(s) = &self.summary {
            node = node.summary(s.clone());
        }
        if !self.children.is_empty() {
            node = node.lazy(emit_items, (self.children.clone(), base));
        }
        node
    }
}

/// Expander: the nodes of header outline items (a folder list can be
/// input-sized), converted as they are emitted.
async fn emit_items(cx: Cx, (items, base): (Arc<Vec<Item>>, Span)) -> Result<()> {
    for item in items.iter() {
        cx.checkpoint().await;
        cx.emit(item.node(base));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Decoding folders

/// How a folder decodes: its last coder decompresses the packed stream, and
/// the coders before it filter that output, last to first.
#[derive(Clone, Debug)]
struct Plan {
    codec: Codec,
    /// The decompressor's output size.
    size: u64,
    /// Post-filters, in the order they are applied, with the start offset
    /// of a branch converter.
    post: Vec<(Post, u32)>,
    /// For a BCJ2 folder: the (offset, length) of its main, CALL, JMP and
    /// range coder packed streams, relative to the folder's packed data.
    /// The codec reads them interleaved (see `codec::bcj2::Schedule`).
    pieces: Vec<(u64, u64)>,
    /// For an encrypted folder: its AES coder, which decrypts the packed
    /// stream before `codec` sees it (for a BCJ2 folder, the first of its
    /// AES coders, which all derive one key).
    aes: Option<Arc<Lock>>,
    /// For an encrypted BCJ2 folder: the IV of the AES coder in front of
    /// each of its four streams, if encrypted.
    ivs: Vec<Option<[u8; 16]>>,
}

/// The decoding plan of `f`, or why it cannot be decoded: a chain of
/// one-input, one-output coders (the packed stream feeds a decompressor,
/// whose output runs through filters), or a BCJ2 folder.
fn plan(f: &Folder, unlock: Unlock) -> std::result::Result<Plan, String> {
    let n = f.coders.len();
    let simple = f.packed == 1
        && n > 0
        && f.coders.iter().all(|c| c.ins == 1 && c.outs == 1)
        && f.binds.len() == n.saturating_sub(1);
    if !simple {
        return bcj2_plan(f, unlock);
    }
    // With one-in, one-out coders, input and output indices are coder
    // indices. The packed stream feeds the coder whose input is unbound;
    // each bind pair (input, output) feeds coder `output`'s result to coder
    // `input`.
    let first = (0..to_u64(n))
        .find(|i| f.binds.iter().all(|&(inp, _)| inp != *i))
        .ok_or_else(|| f.methods())?;
    let mut order = vec![first];
    let mut at = first;
    while let Some(&(next, _)) = f.binds.iter().find(|&&(_, out)| out == at) {
        if order.contains(&next) || order.len() >= n {
            return Err(f.methods());
        }
        order.push(next);
        at = next;
    }
    if order.len() != n {
        return Err(f.methods());
    }
    let coder = |i: u64| f.coders.get(to_usize(i));
    // An AES coder decrypts the packed stream for the next coder (or is
    // the only one: encrypted, not compressed).
    let mut aes = None;
    let mut first = first;
    let mut rest = order.get(1..).unwrap_or_default();
    if let Some(c) = coder(first).filter(|c| c.id == AES_ID) {
        aes = Some(Arc::new(Lock {
            props: AesProps::parse(&c.props),
            unlock,
        }));
        if let Some((&next, more)) = rest.split_first() {
            first = next;
            rest = more;
        }
    }
    let last = coder(first).ok_or_else(|| f.methods())?;
    let size = f.unpack_sizes.get(to_usize(first)).copied().unwrap_or(0);
    let codec = if last.id == AES_ID {
        Codec::Stored
    } else {
        decompressor(last, size)?
    };
    let mut post = Vec::new();
    for &i in rest {
        let c = coder(i).ok_or_else(|| f.methods())?;
        let id = c.id.as_slice();
        // Branch converters, with an optional 4-byte start offset (7-Zip
        // writes one for ARM64 and RISC-V, `-mf=ARM64:4096`), which must be
        // a multiple of the instruction alignment.
        post.push(if let Some(kind) = branch(id) {
            let start = match c.props.len() {
                0 => 0,
                4 => u32_le(&c.props, 0).unwrap_or(0),
                _ => {
                    return Err(format!(
                        "{} with {} property bytes",
                        method_name(id),
                        c.props.len()
                    ));
                }
            };
            if start.checked_rem(kind.alignment()) != Some(0) {
                return Err(format!(
                    "{} with a misaligned start offset",
                    method_name(id)
                ));
            }
            (kind, start)
        } else {
            match id {
                [0x03] => (
                    Post::Delta(
                        usize::from(c.props.first().copied().unwrap_or(0)).saturating_add(1),
                    ),
                    0,
                ),
                id => return Err(method_name(id)),
            }
        });
    }
    Ok(Plan {
        codec,
        size,
        post,
        pieces: Vec::new(),
        aes,
        ivs: Vec::new(),
    })
}

/// The codec of a decompressing coder with `size` bytes of output.
fn decompressor(c: &Coder, size: u64) -> std::result::Result<Codec, String> {
    Ok(match c.id.as_slice() {
        [0x00] => Codec::Stored,
        [0x21] => Codec::Lzma2 {
            dict: c
                .props
                .first()
                .and_then(|&p| crate::codec::lzma::lzma2_dict(p)),
        },
        [0x03, 0x01, 0x01] => {
            let props = c
                .props
                .first()
                .and_then(|&b| crate::codec::lzma::Props::from_byte(b).ok())
                .ok_or_else(|| "LZMA with invalid properties".to_owned())?;
            Codec::LzmaRaw {
                props,
                size: Some(to_usize(size)),
                dict: crate::bytes::u32_le(&c.props, 1),
            }
        }
        [0x04, 0x01, 0x08] => Codec::Deflate,
        [0x04, 0x01, 0x09] => Codec::Deflate64,
        // Properties: the model order, then its memory size.
        [0x03, 0x04, 0x01] => match (c.props.first(), u32_le(&c.props, 1)) {
            (Some(&order), Some(mem)) => Codec::Ppmd7 { order, mem, size },
            _ => return Err("PPMd with invalid properties".to_owned()),
        },
        [0x04, 0x02, 0x02] => Codec::Bzip2,
        [0x04, 0xf7, 0x11, 0x01] => Codec::Zstd,
        [0x04, 0xf7, 0x11, 0x04] => Codec::Lz4Frame,
        id => return Err(method_name(id)),
    })
}

/// The plan of a BCJ2 folder: the BCJ2 coder's output is the folder's,
/// and each of its four inputs (main, CALL, JMP, range coder) is a packed
/// stream, either as is or through one decompressing coder, and either
/// way maybe decrypted first by an AES coder of its own (`7z a -p` with
/// BCJ2: "BCJ2 LZMA2 LZMA LZMA 7zAES ×4", each AES coder with its own IV
/// and one key). The decoder reads all four side by side, so its input
/// interleaves them (see `folder_output`).
fn bcj2_plan(f: &Folder, unlock: Unlock) -> std::result::Result<Plan, String> {
    use crate::codec::bcj2;
    let fail = || f.methods();
    if f.coders.iter().any(|c| c.outs != 1) || f.binds.len() != f.coders.len().saturating_sub(1) {
        return Err(fail());
    }
    // With one output per coder, output indices are coder indices.
    let last = (0..to_u64(f.coders.len()))
        .find(|i| f.binds.iter().all(|&(_, out)| out != *i))
        .ok_or_else(fail)?;
    let bcj2 = f.coders.get(to_usize(last)).ok_or_else(fail)?;
    if bcj2.id != [0x03, 0x03, 0x01, 0x1b] || bcj2.ins != 4 {
        return Err(fail());
    }
    let base = |c: u64| {
        f.coders
            .iter()
            .take(to_usize(c))
            .fold(0u64, |a, c| a.saturating_add(c.ins))
    };
    let mut pack_offsets = Vec::new();
    let mut at = 0u64;
    for &len in &f.pack_sizes {
        pack_offsets.push(at);
        at = at.saturating_add(len);
    }
    // Each BCJ2 input: its packed stream, codec, decoded size and AES
    // coder. Every other coder must feed one of them from a packed
    // stream: a decompressor, an AES coder, or an AES coder feeding a
    // decompressor.
    let mut inputs = Vec::new();
    let mut aes: Option<AesProps> = None;
    for j in 0..4u64 {
        let mut input = base(last).saturating_add(j);
        let mut codec = None;
        let mut iv = None;
        let mut size = None;
        while let Some(&(_, out)) = f.binds.iter().find(|&&(inp, _)| inp == input) {
            let c = f.coders.get(to_usize(out)).ok_or_else(fail)?;
            // At most a decompressor, then an AES coder before it.
            if c.ins != 1 || out == last || iv.is_some() {
                return Err(fail());
            }
            let out_size = f.unpack_sizes.get(to_usize(out)).copied().unwrap_or(0);
            if c.id == AES_ID {
                let props = AesProps::parse(&c.props)?;
                iv = Some(props.iv);
                match &aes {
                    Some(first) if first.cycles != props.cycles || first.salt != props.salt => {
                        return Err("AES-256 coders with different keys".to_owned());
                    }
                    Some(_) => {}
                    None => aes = Some(props),
                }
            } else {
                if codec.is_some() {
                    return Err(fail());
                }
                codec = Some(decompressor(c, out_size)?);
                size = Some(out_size);
            }
            input = base(out);
        }
        let p = f
            .pack_inputs
            .iter()
            .position(|&i| i == input)
            .ok_or_else(fail)?;
        let offset = pack_offsets.get(p).copied().ok_or_else(fail)?;
        let len = f.pack_sizes.get(p).copied().ok_or_else(fail)?;
        // Decrypted only, the stream is as long as its packed bytes,
        // padded to a whole block (BCJ2 reads no further than it needs).
        // Decrypted and decompressed, the size bounds every stage's output
        // (`bcj2::Stream`), the decryption's too, which may be longer (8
        // bytes of CALL targets from a 16-byte block); the decompressor
        // stops at its own size.
        let size = match (size, iv) {
            (Some(size), Some(_)) => size.max(len),
            (Some(size), None) => size,
            (None, _) => len,
        };
        inputs.push((offset, len, codec.unwrap_or(Codec::Stored), size, iv));
    }
    let mut pieces = Vec::new();
    let mut streams = Vec::new();
    let mut ivs = Vec::new();
    for (offset, len, codec, size, iv) in inputs {
        pieces.push((offset, len));
        streams.push(bcj2::Stream { len, codec, size });
        ivs.push(iv);
    }
    let streams: [bcj2::Stream; 4] = streams.try_into().map_err(|_| fail())?;
    let size = f.unpack_sizes.get(to_usize(last)).copied().unwrap_or(0);
    let params = bcj2::Params { streams, size };
    Ok(Plan {
        codec: Codec::Bcj2(Arc::new(params)),
        size,
        post: Vec::new(),
        pieces,
        aes: aes.map(|props| {
            Arc::new(Lock {
                props: Ok(props),
                unlock,
            })
        }),
        ivs,
    })
}

/// The branch converter (BCJ) a coder ID names, in its short (xz-style)
/// or long (`03 03 ..`) form.
fn branch(id: &[u8]) -> Option<Post> {
    Some(match id {
        [0x04] | [0x03, 0x03, 0x01, 0x03] => Post::X86,
        [0x05] | [0x03, 0x03, 0x02, 0x05] => Post::PowerPc,
        [0x06] | [0x03, 0x03, 0x04, 0x01] => Post::Ia64,
        [0x07] | [0x03, 0x03, 0x05, 0x01] => Post::Arm,
        [0x08] | [0x03, 0x03, 0x07, 0x01] => Post::ArmThumb,
        [0x09] | [0x03, 0x03, 0x08, 0x05] => Post::Sparc,
        [0x0a] => Post::Arm64,
        [0x0b] => Post::RiscV,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Encryption (7zAES)

/// The AES-256 coder's method ID.
const AES_ID: [u8; 4] = [0x06, 0xf1, 0x07, 0x01];

/// The most key derivation rounds (as a power of two) 7-Zip accepts; it
/// reports more as an unsupported method (checked with 7-Zip 26.03).
const MAX_CYCLES: u8 = 24;

/// Bytes of a folder's output decoded to check a password: the folder
/// itself or its first file if no larger and it has a CRC, else this
/// much (a wrong key turns the stream to garbage, which LZMA, LZMA2 and
/// the other decompressors reject within a few hundred bytes).
const VERIFY_LEN: u64 = 64 * 1024;

/// The AES coder's properties: the key derivation's rounds (a power of
/// two, or `sevenzip::RAW_KEY`), its salt and the CBC IV. The first byte
/// holds the power in bits 0-5 and, in bits 7 and 6, one more byte each
/// of salt and IV; if either is set, a second byte holds as many again in
/// its high and low nibbles; then the salt and the IV (zero-padded to a
/// block). Checked against archives from 7-Zip 25.01 (no salt, a 16-byte
/// IV: `53 0f` and the IV).
#[derive(Clone, Debug)]
struct AesProps {
    cycles: u8,
    salt: Vec<u8>,
    iv: [u8; 16],
}

impl AesProps {
    fn parse(p: &[u8]) -> std::result::Result<AesProps, String> {
        let invalid = || "AES-256 with invalid properties".to_owned();
        let &first = p.first().ok_or_else(invalid)?;
        let cycles = first & 0x3f;
        let (salt, iv) = if first & 0xc0 == 0 {
            if p.len() != 1 {
                return Err(invalid());
            }
            (&[][..], &[][..])
        } else {
            let &second = p.get(1).ok_or_else(invalid)?;
            let salt_len = usize::from(first >> 7).saturating_add(usize::from(second >> 4));
            let iv_len = usize::from((first >> 6) & 1).saturating_add(usize::from(second & 0x0f));
            let salt_end = salt_len.saturating_add(2);
            if p.len() != salt_end.saturating_add(iv_len) {
                return Err(invalid());
            }
            (
                p.get(2..salt_end).unwrap_or_default(),
                p.get(salt_end..).unwrap_or_default(),
            )
        };
        if cycles > MAX_CYCLES && cycles != sevenzip::RAW_KEY {
            return Err(format!(
                "AES-256 with 2^{cycles} key derivation rounds (7-Zip allows at most 2^{MAX_CYCLES})"
            ));
        }
        let mut block = [0u8; 16];
        for (b, v) in block.iter_mut().zip(iv) {
            *b = *v;
        }
        Ok(AesProps {
            cycles,
            salt: salt.to_vec(),
            iv: block,
        })
    }
}

/// Bytes of a stored folder's output (AES and no decompressor, as 7-Zip
/// writes `-mx0`) decrypted to check a password against a CRC: nothing
/// else rejects a wrong key there. Decrypting is cheap, and it streams.
const STORED_VERIFY_LEN: u64 = 64 << 20;

/// What unlocks an encrypted folder: the realm of its password (the
/// archive: one password serves the header and every folder) and the
/// CRCs of the start of its output to check a password against.
#[derive(Clone, Debug)]
struct Unlock {
    realm: Span,
    /// The folder's output size and CRC-32, if recorded.
    folder: (u64, Option<u32>),
    /// The size and CRC-32 of the folder's first stream, if known.
    first: Option<(u64, Option<u32>)>,
    /// Another folder of the archive that checks a password on its own,
    /// for a folder that cannot (see [`verifier`]).
    verifier: Option<Arc<Verifier>>,
}

impl Unlock {
    /// For folder `f` of the archive at `realm`, whose first stream has
    /// `first` (size, CRC).
    fn new(realm: Span, f: &Folder, first: Option<(u64, Option<u32>)>) -> Self {
        Unlock {
            realm,
            folder: (f.unpack_size(), f.crc),
            first,
            verifier: None,
        }
    }

    fn with_verifier(mut self, verifier: Option<Arc<Verifier>>) -> Self {
        self.verifier = verifier;
        self
    }

    /// The length and CRC-32 of the folder's first bytes, if recorded and
    /// at most `limit` bytes: the whole folder's, else its first stream's.
    fn check(&self, limit: u64) -> Option<(u64, u32)> {
        match (self.folder, self.first) {
            ((size, Some(crc)), _) if size <= limit => Some((size, crc)),
            (_, Some((size, Some(crc)))) if size <= limit => Some((size, crc)),
            _ => None,
        }
    }
}

/// The padding of a stored encrypted folder: AES encrypts whole blocks,
/// and 7-Zip fills the last one with zeros (its filter coder pads with
/// them; checked on archives from 7-Zip 26.03). Returns the offset of the
/// last block in the packed stream and how many bytes of it are padding,
/// if the packed stream holds it.
fn padding(size: u64, packed: u64) -> Option<(u64, usize)> {
    let tail = size % 16;
    if tail == 0 {
        return None;
    }
    let block = size.saturating_sub(tail);
    (packed >= block.saturating_add(16)).then(|| (block, to_usize(16u64.saturating_sub(tail))))
}

/// Padding bytes that check a password on their own (as a CRC-32 does).
const PADDING_CHECK: usize = 4;

/// The CRC a stored encrypted folder of `size` bytes (`packed` encrypted)
/// checks a password against, if any, or why it cannot be checked: with
/// neither a CRC nor enough padding, a wrong password would only show as
/// garbage.
fn stored_check(
    unlock: &Unlock,
    size: u64,
    packed: u64,
) -> std::result::Result<Option<(u64, u32)>, String> {
    let pad = padding(size, packed).map_or(0, |p| p.1);
    let check = unlock.check(STORED_VERIFY_LEN);
    if check.is_none() && pad < PADDING_CHECK {
        return Err(format!(
            "encrypted, stored without a CRC (of at most {}) or padding to check a password against",
            fmt::size(STORED_VERIFY_LEN)
        ));
    }
    Ok(check)
}

/// An encrypted folder's AES coder.
#[derive(Clone, Debug)]
struct Lock {
    /// Its properties, or why they are unusable (reported when the folder
    /// is decoded).
    props: std::result::Result<AesProps, String>,
    unlock: Unlock,
}

impl Lock {
    /// What the folder of `plan`, packed in `packed` bytes, checks a
    /// password against on its own: the CRC of its first bytes, or none
    /// (a decompressor fails on a wrong key; a stored folder's padding is
    /// long enough), or why it cannot (a stored folder with neither).
    fn own_check(
        &self,
        plan: &Plan,
        packed: u64,
    ) -> std::result::Result<Option<(u64, u32)>, String> {
        if plan.codec == Codec::Stored {
            stored_check(&self.unlock, plan.size, packed)
        } else {
            Ok(self.unlock.check(VERIFY_LEN))
        }
    }
}

/// A folder that checks a password on its own, for the folders of the
/// same archive that cannot (a stored folder with no CRC within
/// [`STORED_VERIFY_LEN`] and too little padding): 7-Zip encrypts every
/// folder of an archive with one password, so a password this folder
/// accepts is the archive's.
#[derive(Debug)]
struct Verifier {
    span: Span,
    plan: Plan,
}

/// The verifier of the archive's folders packed at `spans`: the encrypted
/// folder checked most cheaply on its own (fewest bytes decoded; the
/// first of equals), if any can be. Only when some encrypted folder
/// cannot check a password on its own.
async fn verifier(cx: &Cx, archive: &Archive, file: Span, spans: &[Span]) -> Option<Arc<Verifier>> {
    let mut best: Option<(u64, Span, Plan)> = None;
    let mut needed = false;
    let mut first_stream = 0usize;
    for (f, &span) in archive.streams.folders.iter().zip(spans) {
        cx.checkpoint().await;
        let first = first_stream;
        first_stream = first_stream.saturating_add(to_usize(f.streams));
        let Ok(plan) = plan(f, Unlock::new(file, f, first_of(archive, first))) else {
            continue;
        };
        let Some(lock) = plan.aes.clone() else {
            continue;
        };
        if lock.props.is_err() {
            continue;
        }
        let Ok(check) = lock.own_check(&plan, span.len) else {
            needed = true;
            continue;
        };
        // Bytes decoded to check it.
        let cost = match (check, plan.codec == Codec::Stored) {
            (Some((len, _)), _) => len,
            (None, true) => 0,
            (None, false) => plan.size.min(VERIFY_LEN),
        };
        if best.as_ref().is_none_or(|b| cost < b.0) {
            best = Some((cost, span, plan));
        }
    }
    if !needed {
        return None;
    }
    best.map(|(_, span, plan)| Arc::new(Verifier { span, plan }))
}

/// Keys derived for an archive: (rounds, salt, attempt or `None` once
/// verified, key). Keyed by the attempt (answers are fixed per attempt),
/// so a folder after the first neither asks again nor derives again.
type KeyCache = std::sync::Mutex<Vec<(u8, Vec<u8>, Option<u32>, [u8; 32])>>;

fn cached_key(cache: &KeyCache, props: &AesProps, attempt: Option<u32>) -> Option<[u8; 32]> {
    cache.lock().ok().and_then(|found| {
        found
            .iter()
            .find(|(c, s, a, _)| *c == props.cycles && *s == props.salt && *a == attempt)
            .map(|e| e.3)
    })
}

fn cache_key(cache: &KeyCache, props: &AesProps, attempt: Option<u32>, key: [u8; 32]) {
    if let Ok(mut found) = cache.lock() {
        found.push((props.cycles, props.salt.clone(), attempt, key));
    }
}

/// The key `props` derive from `secret`, the answer to `attempt`
/// (derived in budgeted steps, once per attempt).
async fn derive(
    cx: &Cx,
    cache: &KeyCache,
    props: &AesProps,
    attempt: u32,
    secret: &crate::secret::Secret,
) -> [u8; 32] {
    if let Some(key) = cached_key(cache, props, Some(attempt)) {
        return key;
    }
    let password = sevenzip::utf16le(secret.expose());
    let mut kdf = sevenzip::SevenZipKdf::new(&password, &props.salt, props.cycles);
    crate::codec::crypto::run(cx, &mut kdf).await;
    let key = kdf.key();
    cache_key(cache, props, Some(attempt), key);
    key
}

/// The AES key of an encrypted folder: asks for the archive's password
/// and derives the key (in budgeted steps) until one decodes the start of
/// the folder (and matches its CRC where known); 7z has no password check
/// value, so a wrong password shows as a decoding error or a CRC mismatch.
/// A folder that cannot check a password on its own is checked on its
/// archive's [`Verifier`].
async fn folder_key(cx: &Cx, span: Span, plan: &Plan, lock: &Lock) -> Result<[u8; 32]> {
    use crate::secret::{MAX_ATTEMPTS, SecretRequest};
    const PROMPT: &str = "Password for the encrypted 7z archive";
    let props = lock
        .props
        .as_ref()
        .map_err(|why| Diagnostic::unsupported(why.clone()).at(span))?;
    let realm = lock.unlock.realm;
    let cache = match cx.cached::<KeyCache>(realm, "7z keys") {
        Some(cache) => cache,
        None => {
            let cache = Arc::new(KeyCache::default());
            cx.cache(realm, "7z keys", cache.clone());
            cache
        }
    };
    if let Some(key) = cached_key(&cache, props, None) {
        return Ok(key);
    }
    // The folder a password is checked on: this one, or, for a stored
    // folder with neither a CRC nor padding (where a wrong password could
    // only show as garbage), the archive's verifier. Decided from the
    // archive alone, before asking.
    let (on, plan_on, lock_on, check) = match lock.own_check(plan, span.len) {
        Ok(check) => (span, plan, lock, check),
        Err(why) => {
            let refuse = || Diagnostic::unsupported(why.clone()).at(span);
            let v = lock.unlock.verifier.as_ref().ok_or_else(refuse)?;
            let lock_on = v.plan.aes.as_deref().ok_or_else(refuse)?;
            let check = lock_on
                .own_check(&v.plan, v.span.len)
                .map_err(|_| refuse())?;
            (v.span, &v.plan, lock_on, check)
        }
    };
    let props_on = lock_on
        .props
        .as_ref()
        .map_err(|why| Diagnostic::unsupported(why.clone()).at(span))?;
    // Refused up front only for what the host's work limit could not
    // finish (see `docs/DISSECTORS.md`); without one, it runs.
    for p in [props, props_on] {
        if p.cycles != sevenzip::RAW_KEY
            && let Some(max) = cx.limits().max_work
            && (1u64 << p.cycles) > max.saturating_mul(2) / 5
        {
            return Err(Diagnostic::limit(format!(
                "key derivation too expensive (2^{} SHA-256 rounds) for the work limit",
                p.cycles
            ))
            .at(span));
        }
    }
    let stored = plan_on.codec == Codec::Stored;
    for attempt in 0..MAX_ATTEMPTS {
        let Some(secret) = cx
            .secret(SecretRequest::password(realm, PROMPT, attempt))
            .await
        else {
            let why = if attempt == 0 {
                "encrypted (no password)"
            } else {
                "encrypted (wrong password)"
            };
            return Err(Diagnostic::unsupported(why).at(span));
        };
        let key_on = derive(cx, &cache, props_on, attempt, &secret).await;
        let padded = !stored || padding_is_zero(cx, on, plan_on, props_on, &key_on).await?;
        // Padding long enough to check on its own needs no CRC.
        let checked = stored && check.is_none();
        if padded && (checked || trial(cx, on, plan_on, &key_on, check).await?) {
            cache_key(&cache, props_on, None, key_on);
            // The same password, with this folder's own rounds and salt.
            let key = derive(cx, &cache, props, attempt, &secret).await;
            if cached_key(&cache, props, None).is_none() {
                cache_key(&cache, props, None, key);
            }
            return Ok(key);
        }
    }
    Err(Diagnostic::unsupported("encrypted (wrong password)").at(span))
}

/// Whether the padding of the stored encrypted folder at `span` decrypts
/// to zeros with `key` (see [`padding`]); true if it has none. Only the
/// last block is decrypted: in CBC mode it needs just the block before.
async fn padding_is_zero(
    cx: &Cx,
    span: Span,
    plan: &Plan,
    props: &AesProps,
    key: &[u8; 32],
) -> Result<bool> {
    use crate::codec::filters::ByteFilter;
    let Some((block, pad)) = padding(plan.size, span.len) else {
        return Ok(true);
    };
    let iv = match block.checked_sub(16) {
        Some(before) => cx.read(span.sub_exact(before, 16)?).await?.to_vec(),
        None => props.iv.to_vec(),
    };
    let cipher = cx.read(span.sub_exact(block, 16)?).await?;
    let mut aes = crate::codec::crypto::stream::AesCbcRaw::new(&Key::new([&key[..], &iv].concat()));
    let mut plain = Vec::new();
    for &b in cipher.iter() {
        aes.byte(b, &mut plain)?;
    }
    Ok(plain
        .get(16usize.saturating_sub(pad)..)
        .is_some_and(|p| p.len() == pad && p.iter().all(|&b| b == 0)))
}

/// Whether the folder at `span` decodes with `key`: its first bytes (up to
/// [`VERIFY_LEN`], or as many as `check` covers, whose CRC must then
/// match). Decoded in memory, a window at a time (the CRC is computed as
/// output comes): a derived source would be memoized whatever the key.
async fn trial(
    cx: &Cx,
    span: Span,
    plan: &Plan,
    key: &[u8; 32],
    check: Option<(u64, u32)>,
) -> Result<bool> {
    use crate::codec::pipeline::Status;
    let codec = plan.codec(Some(key));
    let Some(mut decoder) = codec.decoder() else {
        return Ok(false);
    };
    let span = packed_input(cx, span, plan).await?;
    let want = check.map_or(plan.size.min(VERIFY_LEN), |c| c.0);
    // A good stream gives `want` bytes from about as much input; garbage
    // makes the decoder ask for more until the input ends, so stop at a
    // generous multiple (block-based codecs need a whole block).
    let cap = span.len.min(want.saturating_mul(2).saturating_add(4 << 20));
    let limit = to_usize(cx.limits().max_derived);
    let mut input = Vec::new();
    let mut out = Vec::new();
    // Input bytes read, and output bytes released (before `out`).
    let mut fed = 0u64;
    let mut released = 0u64;
    // Output bytes folded into the CRC, which runs over the first `want`.
    let mut summed = 0u64;
    let mut crc = u32::MAX;
    let mut eof = span.len == 0;
    loop {
        let status = decoder.decode(&input, eof, &mut out, 16 * 1024, limit);
        // Fold the new output (up to `want`) into the CRC.
        let held = released.saturating_add(to_u64(out.len())).min(want);
        if held > summed {
            let from = to_usize(summed.saturating_sub(released));
            let to = to_usize(held.saturating_sub(released));
            crc = crate::codec::crc::crc32_update(crc, out.get(from..to).unwrap_or_default());
            summed = held;
        }
        let done = summed >= want;
        match status {
            Ok(Status::Done) => break,
            Ok(Status::More) if done => break,
            Ok(Status::More) => cx.checkpoint().await,
            Ok(Status::NeedInput) if done => break,
            Ok(Status::NeedInput) => {
                if eof || fed >= cap {
                    return Ok(false);
                }
                let n = (1u64 << 20).min(cap.saturating_sub(fed));
                let data = cx.read(span.sub(fed, n)).await?;
                eof = to_u64(data.len()) < n || fed.saturating_add(n) >= span.len;
                input.extend_from_slice(&data);
                fed = fed.saturating_add(to_u64(data.len()));
                cx.progress(summed, want);
            }
            Err(_) => return Ok(false),
        }
        // Drop what the decoder no longer needs (summed output only).
        let n = decoder
            .releasable_output(out.len())
            .min(to_usize(summed.saturating_sub(released)));
        if n > 0 {
            out.drain(..n);
            decoder.release_output(n);
            released = released.saturating_add(to_u64(n));
        }
        let n = decoder.releasable_input().min(input.len());
        if n > 0 {
            input.drain(..n);
            decoder.release_input(n);
        }
    }
    if summed < want {
        return Ok(false);
    }
    Ok(match check {
        Some((_, want)) => crc ^ u32::MAX == want,
        None => true,
    })
}

/// Folders larger than this are decoded on demand.
const LAZY_THRESHOLD: u64 = 1024 * 1024;

impl Plan {
    /// The whole folder as one codec: the decryption with `key` (for an
    /// encrypted folder), the decompressor, then the filters (each a
    /// streaming stage of a chain).
    fn codec(&self, key: Option<&[u8; 32]>) -> Codec {
        // An encrypted BCJ2 folder: each encrypted stream is decrypted
        // with its own IV before its decompressor.
        if let (Codec::Bcj2(params), Some(key)) = (&self.codec, key)
            && self.ivs.iter().any(Option::is_some)
        {
            let mut params = (**params).clone();
            for (s, iv) in params.streams.iter_mut().zip(&self.ivs) {
                let Some(iv) = iv else { continue };
                let aes = Codec::AesCbcRaw(Key::new([&key[..], &iv[..]].concat()));
                s.codec = match &s.codec {
                    Codec::Stored => aes,
                    codec => {
                        Codec::chain("7z coders", "7z coders (lazy)", vec![aes, codec.clone()])
                    }
                };
            }
            return Codec::Bcj2(Arc::new(params));
        }
        let mut stages = Vec::new();
        if let (Some(lock), Some(key)) = (&self.aes, key)
            && let Ok(props) = &lock.props
        {
            stages.push(Codec::AesCbcRaw(Key::new(
                [&key[..], &props.iv[..]].concat(),
            )));
        }
        if self.codec != Codec::Stored || stages.is_empty() {
            stages.push(self.codec.clone());
        }
        stages.extend(self.post.iter().map(|&(post, start)| match start {
            0 => Codec::PostFilter(post),
            start => Codec::PostFilterAt { post, start },
        }));
        match <[Codec; 1]>::try_from(stages) {
            Ok([one]) => one,
            Err(stages) => Codec::chain("7z coders", "7z coders (lazy)", stages),
        }
    }

    /// Whether the folder's packed stream is its output.
    fn is_stored(&self) -> bool {
        self.codec == Codec::Stored && self.post.is_empty() && self.aes.is_none()
    }

    /// What decoding the folder does, for its annotation.
    fn verb(&self) -> &'static str {
        match (&self.aes, &self.codec) {
            (None, codec) => codec.verb(),
            (Some(_), Codec::Stored) => "decrypted",
            (Some(_), _) => "decrypted and decompressed",
        }
    }
}

/// The decoded output of the folder packed at `span`: lazily decoded when
/// large, else decoded in full. An encrypted folder asks for the archive's
/// password first.
async fn folder_output(cx: &Cx, span: Span, plan: &Plan) -> Result<(Span, Option<Diagnostic>)> {
    let key = match &plan.aes {
        Some(lock) => Some(folder_key(cx, span, plan, lock).await?),
        None => None,
    };
    let codec = plan.codec(key.as_ref());
    if codec == Codec::Stored {
        return Ok((span, None));
    }
    let span = packed_input(cx, span, plan).await?;
    if plan.size > LAZY_THRESHOLD && plan.size <= span.len.saturating_mul(codec.max_ratio()) {
        let decoded = cx.decode_lazy(span, &codec, plan.size)?;
        return Ok((decoded, None));
    }
    // Decrypted but not decompressed: the cipher's output is padded to a
    // whole block. Cut to the folder's size.
    let expected = (plan.aes.is_none() || plan.codec != Codec::Stored).then_some(plan.size);
    let decoded = decode_span(cx, span, &codec, expected).await?;
    Ok((decoded.span.sub(0, plan.size), decoded.error))
}

/// The input of the folder packed at `span`'s codec: the packed data, or
/// for a BCJ2 folder its packed streams, interleaved as the codec reads
/// them, up to the first piece the folder's data does not hold whole (the
/// codec then finds its input short). Each piece but the last of each
/// stream is a full `bcj2::PIECE`, so the list is bounded by the data.
async fn packed_input(cx: &Cx, span: Span, plan: &Plan) -> Result<Span> {
    if plan.pieces.is_empty() {
        return Ok(span);
    }
    let lens: [u64; 4] = std::array::from_fn(|k| plan.pieces.get(k).map_or(0, |p| p.1));
    let mut pieces = Vec::new();
    for (k, at, len) in crate::codec::bcj2::Schedule::new(lens) {
        let start = plan.pieces.get(k).map_or(0, |p| p.0).saturating_add(at);
        match span.sub_exact(start, len) {
            Ok(piece) => pieces.push(piece),
            Err(_) => {
                pieces.push(span.sub(start, len));
                break;
            }
        }
        if pieces.len().is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    cx.add_pieces(
        crate::span::Origin {
            parent: span,
            transform: "7z packed streams",
        },
        pieces,
    )
}

/// Expander: decodes a folder and dissects `len` bytes at `offset` of its
/// output (a file, or the whole folder), checking its CRC-32 if recorded.
async fn folder_part(
    cx: Cx,
    (input, span, plan, offset, len, crc): (Input, Span, Arc<Plan>, u64, u64, Option<u32>),
) -> Result<()> {
    let (out, error) = folder_output(&cx, span, &plan).await?;
    if let Some(e) = error {
        cx.diag(e);
    }
    cx.annotate(format!("{:#x} bytes {}", len, plan.verb()));
    let part = out.sub(offset, len);
    check_crc(&cx, part, len, crc).await?;
    dissect_or_data(cx, input.nested(part)).await
}

/// A "CRC32" node comparing `span` (which should hold `len` bytes) with
/// the recorded CRC-32, for content small enough to read just for that.
async fn check_crc(cx: &Cx, span: Span, len: u64, crc: Option<u32>) -> Result<()> {
    let Some(want) = crc else { return Ok(()) };
    if len > super::rar::CRC_LIMIT {
        return Ok(());
    }
    let (got, read) = super::rar::crc_of(cx, span).await?;
    let node = Node::new("CRC32").value(hex(got, 64));
    cx.emit(if read < len {
        node.diag(Diagnostic::malformed(format!(
            "decoded {read:#x} of {len:#x} bytes"
        )))
    } else if got != want {
        node.diag(Diagnostic::warning(format!(
            "CRC32 mismatch: stored {want:#010x}"
        )))
    } else {
        node.summary("valid")
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sh_span = file.sub(0, SignatureHeader::SIZE);
    let sh = crate::fields::parse(&cx, sh_span, LE, &(), SignatureHeader::layout).await?;
    let raw = cx.read(sh_span).await?;
    let mut sh_node = SignatureHeader::node("Signature header", sh_span, LE)
        .summary(format!("version {}.{}", sh.major, sh.minor));
    if let (Some(covered), Some(stored)) = (raw.get(12..32), u32_le(&raw, 8))
        && crc32(covered) != stored
    {
        sh_node = sh_node.diag(Diagnostic::warning("start header CRC mismatch"));
    }
    cx.emit(sh_node);
    cx.annotate("7-Zip archive");

    let next = file.sub(
        SIGNATURE_HEADER.saturating_add(sh.next_offset),
        sh.next_size,
    );
    if next.len < sh.next_size {
        cx.emit(Node::new("Packed data").span(file.tail(SIGNATURE_HEADER)));
        return Err(Diagnostic::truncated(
            Span::new(next.source, next.offset, sh.next_size),
            next.len,
        ));
    }
    if sh.next_size == 0 {
        cx.annotate("7-Zip archive, empty");
        return Ok(());
    }
    let data = cx.read(next).await?;
    let mut next_node = Node::new("Next header").span(next);
    if crate::formats::util::datakit::crc32_paced(&cx, &data).await != sh.next_crc {
        next_node = next_node.diag(Diagnostic::warning("next header CRC mismatch"));
    }
    let parsed = Parser {
        data: &data,
        at: 0,
        cx: &cx,
    }
    .header()
    .await;
    let mut archive = match parsed {
        Ok(a) => a,
        Err(e) => {
            cx.emit(
                Node::new("Packed data").span(
                    file.sub(
                        SIGNATURE_HEADER,
                        next.offset
                            .saturating_sub(file.offset.saturating_add(SIGNATURE_HEADER)),
                    ),
                ),
            );
            cx.emit(next_node.diag(Diagnostic::malformed(e)));
            return Ok(());
        }
    };
    let mut outline = Arc::new(std::mem::take(&mut archive.outline));
    let mut archive = Arc::new(archive);
    let mut pack_base = SIGNATURE_HEADER.saturating_add(archive.streams.pack_pos);
    // Where packed streams end and the (outer) next header starts.
    let data_end = next
        .offset
        .saturating_sub(file.offset.saturating_add(SIGNATURE_HEADER));
    let mut header = next;

    if archive.encoded {
        let mut methods: Vec<String> = Vec::new();
        for f in &archive.streams.folders {
            cx.checkpoint().await;
            methods.push(f.methods());
        }
        let methods = methods.join(", ");
        let mut packed = 0u64;
        for &s in &archive.streams.pack_sizes {
            cx.checkpoint().await;
            packed = packed.saturating_add(s);
        }
        let header_span = file.sub(pack_base, packed);
        let size = archive
            .streams
            .folders
            .first()
            .map_or(0, Folder::unpack_size);
        let summary = format!("{methods}, {} → {}", fmt::size(packed), fmt::size(size));
        let encrypted = archive
            .streams
            .folders
            .first()
            .is_some_and(|f| f.coders.iter().any(|c| c.id == AES_ID));
        if encrypted {
            // Decrypted when a node needs the files or folders, so the
            // password is asked for only then.
            cx.emit(
                Node::new("Encoded header")
                    .span(header_span)
                    .summary(summary)
                    .lazy(emit_items, (outline, next)),
            );
            let header = Arc::new(Header::Encrypted {
                outer: archive,
                pack_base,
            });
            cx.emit(
                Node::new("Files")
                    .span(header_span)
                    .summary("in the encrypted header")
                    .lazy(list_files, (input, header.clone())),
            );
            cx.emit(
                Node::new("Folders")
                    .span(file.sub(SIGNATURE_HEADER, data_end))
                    .summary("in the encrypted header")
                    .lazy(list_folders, (input, header.clone())),
            );
            cx.emit(
                Node::new("Decoded header")
                    .span(header_span)
                    .summary("kHeader, encrypted")
                    .lazy(decoded_outline, (input, header)),
            );
            cx.annotate(format!("7-Zip archive, encrypted header ({methods})"));
            return Ok(());
        }
        match decode_header(&cx, &archive, file, pack_base).await {
            Ok((span, mut inner)) => {
                cx.emit(
                    Node::new("Encoded header")
                        .span(header_span)
                        .summary(summary)
                        .lazy(emit_items, (outline, next)),
                );
                pack_base = SIGNATURE_HEADER.saturating_add(inner.streams.pack_pos);
                outline = Arc::new(std::mem::take(&mut inner.outline));
                archive = Arc::new(inner);
                header = span;
                next_node = Node::new("Decoded header").span(span);
            }
            Err(e) => {
                let data_len = pack_base.saturating_sub(SIGNATURE_HEADER);
                if data_len > 0 {
                    cx.emit(
                        Node::new("Packed data")
                            .span(file.sub(SIGNATURE_HEADER, data_len))
                            .summary(fmt::size(data_len)),
                    );
                }
                cx.emit(
                    Node::new("Encoded header")
                        .span(header_span)
                        .summary(summary)
                        .diag(e),
                );
                cx.emit(
                    next_node
                        .summary("kEncodedHeader")
                        .lazy(emit_items, (outline, next)),
                );
                cx.annotate(format!(
                    "7-Zip archive, header compressed ({methods}), {} packed",
                    fmt::size(file.len)
                ));
                return Ok(());
            }
        }
    }

    let files = archive.files.count;
    let plain = Arc::new(Header::Plain {
        archive: archive.clone(),
        pack_base,
    });
    let mut methods: Vec<String> = Vec::new();
    for f in &archive.streams.folders {
        cx.checkpoint().await;
        let m = f.methods();
        if methods.last() != Some(&m) {
            methods.push(m);
        }
    }
    cx.emit(
        Node::new("Files")
            .span(header)
            .summary(count(files, "file", "files"))
            .lazy(list_files, (input, plain.clone())),
    );
    cx.emit(
        Node::new("Folders")
            .span(file.sub(SIGNATURE_HEADER, data_end))
            .summary(count(
                to_u64(archive.streams.folders.len()),
                "folder",
                "folders",
            ))
            .lazy(list_folders, (input, plain)),
    );
    cx.emit(
        next_node
            .summary("kHeader")
            .lazy(emit_items, (outline, header)),
    );
    let mut summary = format!("7-Zip archive, {}", count(files, "file", "files"));
    if !methods.is_empty() {
        summary = format!("{summary}, {}", methods.join(", "));
    }
    cx.annotate(summary);
    Ok(())
}

/// Decodes an encoded header (its first folder) and parses the plain header
/// inside: returns the decoded span and the archive it describes.
async fn decode_header(
    cx: &Cx,
    outer: &Archive,
    file: Span,
    pack_base: u64,
) -> Result<(Span, Archive)> {
    let folder = outer
        .streams
        .folders
        .first()
        .ok_or_else(|| Diagnostic::malformed("encoded header without a folder"))?;
    let span = folder_spans(cx, outer, file, pack_base)
        .await
        .first()
        .copied()
        .ok_or_else(|| Diagnostic::malformed("encoded header without a packed stream"))?;
    let p = plan(folder, Unlock::new(file, folder, None))
        .map_err(|why| Diagnostic::unsupported(format!("{why} compression")).at(span))?;
    let (out, error) = folder_output(cx, span, &p).await?;
    if let Some(e) = error {
        return Err(e);
    }
    let bytes = read_all(cx, out).await?;
    match (Parser {
        data: &bytes,
        at: 0,
        cx,
    })
    .header()
    .await
    {
        Ok(a) if !a.encoded => Ok((out, a)),
        Ok(_) => Err(Diagnostic::malformed("encoded header inside an encoded header").at(out)),
        Err(e) => Err(Diagnostic::malformed(e).at(out)),
    }
}

/// Where the files and folders of an archive are described.
enum Header {
    /// In the header read when the archive was opened.
    Plain {
        archive: Arc<Archive>,
        pack_base: u64,
    },
    /// In an encrypted header, decrypted (asking for the password) when a
    /// node needs it.
    Encrypted { outer: Arc<Archive>, pack_base: u64 },
}

impl Header {
    /// The archive and where its packed streams start (relative to the
    /// file), and the decoded header's span for an encrypted one.
    async fn open(&self, cx: &Cx, file: Span) -> Result<(Arc<Archive>, u64, Option<Span>)> {
        match self {
            Header::Plain { archive, pack_base } => Ok((archive.clone(), *pack_base, None)),
            Header::Encrypted { outer, pack_base } => {
                let (span, inner) = decode_header(cx, outer, file, *pack_base).await?;
                let base = SIGNATURE_HEADER.saturating_add(inner.streams.pack_pos);
                Ok((Arc::new(inner), base, Some(span)))
            }
        }
    }
}

/// Expander: the outline of an encrypted header, once decrypted.
async fn decoded_outline(cx: Cx, (input, header): (Input, Arc<Header>)) -> Result<()> {
    let (archive, _, span) = header.open(&cx, input.span).await?;
    let span = span.unwrap_or(input.span);
    emit_items(cx, (Arc::new(archive.outline.clone()), span)).await
}

/// Spans of each folder's first packed stream.
async fn folder_spans(cx: &Cx, archive: &Archive, file: Span, pack_base: u64) -> Vec<Span> {
    let mut out = Vec::new();
    let mut pack_index = 0usize;
    let mut offsets = Vec::new();
    let mut at = pack_base;
    for &s in &archive.streams.pack_sizes {
        cx.checkpoint().await;
        offsets.push((at, s));
        at = at.saturating_add(s);
    }
    for f in &archive.streams.folders {
        cx.checkpoint().await;
        let (start, len) = offsets.get(pack_index).copied().unwrap_or((at, 0));
        // Folders with several packed streams (BCJ2) span all of them.
        let mut total = len;
        for i in 1..f.packed {
            if let Some((_, l)) = offsets.get(pack_index.saturating_add(to_usize(i))) {
                total = total.saturating_add(*l);
            }
        }
        out.push(file.sub(start, total));
        pack_index = pack_index.saturating_add(to_usize(f.packed));
    }
    out
}

async fn list_folders(cx: Cx, (input, header): (Input, Arc<Header>)) -> Result<()> {
    let (archive, pack_base, decrypted) = header.open(&cx, input.span).await?;
    if decrypted.is_some() {
        // Counted once the encrypted header is open.
        cx.annotate(count(
            to_u64(archive.streams.folders.len()),
            "folder",
            "folders",
        ));
    }
    let spans = folder_spans(&cx, &archive, input.span, pack_base).await;
    let verifier = verifier(&cx, &archive, input.span, &spans).await;
    cx.set_count(Count::Exact(to_u64(archive.streams.folders.len())));
    let mut first_stream = 0usize;
    for (i, (f, span)) in archive.streams.folders.iter().zip(spans).enumerate() {
        let first = first_stream;
        first_stream = first_stream.saturating_add(to_usize(f.streams));
        let unlock =
            Unlock::new(input.span, f, first_of(&archive, first)).with_verifier(verifier.clone());
        let methods = f.methods();
        let mut children: Vec<Node> = f
            .coders
            .iter()
            .enumerate()
            .map(|(j, c)| coder_node(j, c))
            .collect();
        children.push(
            Node::new("Unpacked size")
                .value(uint(f.unpack_size(), 64))
                .summary(fmt::size(f.unpack_size())),
        );
        children.push(Node::new("Streams").value(uint(f.streams, 64)));
        children.push(match plan(f, unlock) {
            Ok(p) if p.is_stored() => embedded("Data", input.nested(span)),
            Ok(p) => {
                let size = f.unpack_size();
                Node::new("Data")
                    .span(span)
                    .lazy(folder_part, (input, span, Arc::new(p), 0, size, f.crc))
            }
            Err(why) => unsupported("Data", span, &why),
        });
        cx.push(
            Node::new(format!("Folder {i}"))
                .span(span)
                .summary(format!(
                    "{methods}, {} → {}, {}",
                    fmt::size(span.len),
                    fmt::size(f.unpack_size()),
                    count(f.streams, "stream", "streams")
                ))
                .lazy(emit_nodes, Arc::new(children)),
        )
        .await;
    }
    Ok(())
}

/// A folder's coder, with its properties.
fn coder_node(j: usize, c: &Coder) -> Node {
    let node = Node::new(format!("Coder {j}"))
        .value(text(method_name(&c.id)))
        .summary(format!("{} in, {} out", c.ins, c.outs));
    let bytes = |name: &'static str, b: &[u8]| {
        if b.is_empty() {
            Node::new(name).summary("(none)")
        } else {
            Node::new(name).value(Value::Bytes(b.to_vec()))
        }
    };
    let mut props = Vec::new();
    match c.id.as_slice() {
        id if id == AES_ID => match AesProps::parse(&c.props) {
            Ok(p) => {
                let rounds = if p.cycles == sevenzip::RAW_KEY {
                    "none: the salt and password are the key".to_owned()
                } else {
                    format!("2^{} SHA-256 rounds", p.cycles)
                };
                props.push(
                    Node::new("Key derivation")
                        .value(uint(p.cycles, 8))
                        .summary(rounds),
                );
                props.push(bytes("Salt", &p.salt));
                props.push(Node::new("IV").value(Value::Bytes(p.iv.to_vec())));
            }
            Err(why) => return node.diag(Diagnostic::unsupported(why)),
        },
        [0x03, 0x01, 0x01] => {
            if let Some(p) = c
                .props
                .first()
                .and_then(|&b| crate::codec::lzma::Props::from_byte(b).ok())
            {
                props.push(
                    Node::new("lc/lp/pb")
                        .value(text(format!("{}/{}/{}", p.lc, p.lp, p.pb)))
                        .summary("literal context, literal position and position bits"),
                );
            }
            if let Some(d) = u32_le(&c.props, 1) {
                props.push(dict_node(d));
            }
        }
        [0x21] => {
            if let Some(d) = c
                .props
                .first()
                .and_then(|&p| crate::codec::lzma::lzma2_dict(p))
            {
                props.push(dict_node(d));
            }
        }
        [0x03, 0x04, 0x01] => {
            if let Some(&order) = c.props.first() {
                props.push(Node::new("Order").value(uint(order, 8)));
            }
            if let Some(mem) = u32_le(&c.props, 1) {
                props.push(
                    Node::new("Memory")
                        .value(uint(mem, 32))
                        .summary(fmt::size(u64::from(mem))),
                );
            }
        }
        // Delta: the distance minus one.
        [0x03] if c.props.len() == 1 => {
            let d = c
                .props
                .first()
                .map_or(1, |&d| u16::from(d).saturating_add(1));
            props.push(Node::new("Distance").value(uint(d, 16)));
        }
        // A branch converter: where the code starts.
        id if method_name(id).starts_with("BCJ ") && c.props.len() == 4 => {
            if let Some(start) = u32_le(&c.props, 0) {
                props.push(Node::new("Start offset").value(hex(start, 32)));
            }
        }
        _ if !c.props.is_empty() => props.push(bytes("Properties", &c.props)),
        _ => {}
    }
    if props.is_empty() {
        node
    } else {
        node.lazy(emit_nodes, Arc::new(props))
    }
}

fn dict_node(d: u32) -> Node {
    Node::new("Dictionary size")
        .value(uint(d, 32))
        .summary(fmt::size(u64::from(d)))
}

/// The (size, CRC) of stream `i`.
fn first_of(archive: &Archive, i: usize) -> Option<(u64, Option<u32>)> {
    let size = archive.streams.sizes.get(i).copied()?;
    Some((size, archive.streams.crcs.get(i).copied().flatten()))
}

async fn list_files(cx: Cx, (input, header): (Input, Arc<Header>)) -> Result<()> {
    let file = input.span;
    let (archive, pack_base, decrypted) = header.open(&cx, file).await?;
    if decrypted.is_some() {
        cx.annotate(count(archive.files.count, "file", "files"));
    }
    cx.set_count(Count::Exact(archive.files.count));
    let spans = folder_spans(&cx, &archive, file, pack_base).await;
    let verifier = verifier(&cx, &archive, file, &spans).await;
    // Walk files and substreams together.
    let mut folder = 0usize;
    let mut in_folder = 0u64;
    let mut stream = 0usize;
    let mut offset_in_folder = 0u64;
    for f in archive.files.iter() {
        let mut node = Node::new(f.name.clone());
        let mut children = Vec::new();
        if let Some(t) = f.mtime {
            children.push(Node::new("Modification time").value(Value::filetime(t)));
        }
        if let Some(a) = f.attributes {
            let mut attr = Node::new("Attributes").value(hex(a, 64));
            if a & 0x8000 != 0 {
                // p7zip keeps the Unix mode in the high 16 bits.
                attr = attr.summary(crate::formats::util::arcutil::unix_mode(u64::from(a >> 16)));
            }
            children.push(attr);
        }
        if f.has_stream {
            // Skip folders without streams.
            while archive
                .streams
                .folders
                .get(folder)
                .is_some_and(|fo| in_folder >= fo.streams)
            {
                cx.checkpoint().await;
                folder = folder.saturating_add(1);
                in_folder = 0;
                offset_in_folder = 0;
            }
            let size = archive.streams.sizes.get(stream).copied().unwrap_or(0);
            let crc = archive.streams.crcs.get(stream).copied().flatten();
            let fo = archive.streams.folders.get(folder);
            let span = spans.get(folder).copied().unwrap_or(file.sub(0, 0));
            children.push(
                Node::new("Size")
                    .value(uint(size, 64))
                    .summary(fmt::size(size)),
            );
            children.push(Node::new("Folder").value(uint(to_u64(folder), 64)));
            let methods = fo.map(Folder::methods).unwrap_or_default();
            let first = first_of(&archive, stream.saturating_sub(to_usize(in_folder)));
            let unlock = |fo| Unlock::new(file, fo, first).with_verifier(verifier.clone());
            let content_node = match fo.map(|fo| plan(fo, unlock(fo))) {
                Some(Ok(p)) if p.is_stored() => {
                    let s = span.sub(offset_in_folder, size);
                    node = node.span(s);
                    embedded("Content", input.nested(s))
                }
                Some(Ok(p)) => {
                    node = node.span(span);
                    let mut c = Node::new("Content").span(span).lazy(
                        folder_part,
                        (input, span, Arc::new(p), offset_in_folder, size, crc),
                    );
                    if fo.is_some_and(|f| f.streams > 1) {
                        c = c.summary(format!(
                            "{methods}, in a {} solid block",
                            fmt::size(fo.map_or(0, Folder::unpack_size))
                        ));
                    }
                    c
                }
                Some(Err(why)) => {
                    node = node.span(span);
                    unsupported("Content", span, &why).summary(format!(
                        "{methods}, in a {} solid block",
                        fmt::size(fo.map_or(0, Folder::unpack_size))
                    ))
                }
                None => {
                    node = node.span(span);
                    unsupported("Content", span, &methods).summary(format!(
                        "{methods}, in a {} solid block",
                        fmt::size(fo.map_or(0, Folder::unpack_size))
                    ))
                }
            };
            children.push(content_node);
            node = node.summary(fmt::size(size));
            stream = stream.saturating_add(1);
            in_folder = in_folder.saturating_add(1);
            offset_in_folder = offset_in_folder.saturating_add(size);
        } else {
            node = node.summary(if f.is_dir { "directory" } else { "empty file" });
        }
        if !children.is_empty() {
            node = node.lazy(emit_nodes, Arc::new(children));
        }
        cx.push(node).await;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn unlock(folder: (u64, Option<u32>), first: Option<(u64, Option<u32>)>) -> Unlock {
        Unlock {
            realm: Span::new(crate::span::SourceId::default_host(), 0, 0),
            folder,
            first,
            verifier: None,
        }
    }

    #[test]
    fn stored_padding() {
        // 6 bytes in one block: 10 bytes of padding.
        assert_eq!(padding(6, 16), Some((0, 10)));
        assert_eq!(padding(21, 32), Some((16, 11)));
        // Whole blocks: none. A packed stream short of the block: none.
        assert_eq!(padding(32, 32), None);
        assert_eq!(padding(21, 16), None);
    }

    #[test]
    fn a_stored_folder_without_a_check_is_refused() {
        let big = STORED_VERIFY_LEN + 16;
        // No CRC within reach and whole blocks: nothing to check.
        assert!(stored_check(&unlock((big, Some(1)), Some((big, Some(1)))), big, big).is_err());
        assert!(stored_check(&unlock((64, None), Some((64, None))), 64, 64).is_err());
        // Three bytes of padding are too few on their own; four do.
        assert!(stored_check(&unlock((13, None), None), 13, 16).is_err());
        assert_eq!(stored_check(&unlock((12, None), None), 12, 16), Ok(None));
        // A CRC: the folder's, else the first stream's.
        assert_eq!(
            stored_check(&unlock((64, Some(7)), Some((16, Some(8)))), 64, 64),
            Ok(Some((64, 7)))
        );
        assert_eq!(
            stored_check(&unlock((big, None), Some((16, Some(8)))), big, big),
            Ok(Some((16, 8)))
        );
    }
}
