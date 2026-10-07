//! 7z archives.
//!
//! A 32-byte signature header points at the "next header" at the end of the
//! file. That header is either plain (`kHeader`), describing packed streams,
//! folders (coder chains) and files, or encoded (`kEncodedHeader`): a small
//! streams description of where the real, usually LZMA-compressed, header is
//! packed. Encoded headers are decompressed and then parsed like plain ones.
//!
//! Members of "Copy" folders are dissected in place. Folders whose coders
//! form a simple chain (LZMA, LZMA2, Deflate, BZip2, Zstandard or LZ4, then
//! optionally BCJ x86/ARM/ARM64 or Delta filters) are decoded, and solid
//! folders are split into their files by the substream sizes. Multi-stream
//! coders (BCJ2), PPMd, Deflate64 and encryption are unsupported leaves.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_le, u64_le};
use crate::codec::lzma::Post;
use crate::codec::{crc32, decode_span, read_all};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{count, emit_nodes, hex, human_size, text, uint, unsupported};
use crate::formats::{Codec, Format, Input, Probe, dissect_or_data, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
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
        next_size: u64 "Next header size" .with(|&s, n| n.summary(human_size(s))),
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
    children: Vec<Item>,
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
    /// Files (substreams) in this folder.
    streams: u64,
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
}

#[derive(Clone, Debug, Default)]
struct File {
    name: String,
    has_stream: bool,
    is_dir: bool,
    mtime: Option<u64>,
    attributes: Option<u32>,
}

#[derive(Clone, Debug, Default)]
struct Archive {
    encoded: bool,
    streams: Streams,
    files: Vec<File>,
    outline: Vec<Item>,
}

struct Parser<'a> {
    data: &'a [u8],
    at: usize,
}

type P<T> = std::result::Result<T, &'static str>;

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

    fn digests(&mut self, n: u64) -> P<Item> {
        let start = self.at.saturating_sub(1);
        let defined = self.defined(n)?;
        for d in &defined {
            if *d {
                self.u32()?;
            }
        }
        let crcs = defined.iter().filter(|&&d| d).count();
        Ok(self
            .item("kCRC", start)
            .with_summary(count(to_u64(crcs), "CRC", "CRCs")))
    }

    fn pack_info(&mut self, s: &mut Streams) -> P<Item> {
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
                        s.pack_sizes.push(self.number()?);
                    }
                    children.push(
                        self.item("kSize", at)
                            .with_summary(count(n, "size", "sizes")),
                    );
                }
                0x0a => children.push(self.digests(n)?),
                _ => return Err("unexpected property in pack info"),
            }
        }
        let mut item = self.item("kPackInfo", start).with_summary(format!(
            "{}, at {:#x}",
            count(n, "packed stream", "packed streams"),
            s.pack_pos
        ));
        item.children = children;
        Ok(item)
    }

    fn folder(&mut self) -> P<Folder> {
        let coders = self.count(2)?;
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
        let bind_pairs = outs.saturating_sub(1);
        if bind_pairs > to_u64(self.data.len()) {
            return Err("too many bind pairs");
        }
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
                self.number()?;
            }
        }
        f.streams = 1;
        Ok(f)
    }

    fn unpack_info(&mut self, s: &mut Streams) -> P<Item> {
        let start = self.at.saturating_sub(1);
        self.expect(0x0b)?;
        let n = self.count(2)?;
        if self.byte()? != 0 {
            return Err("external folders are not supported");
        }
        let mut children = Vec::new();
        for i in 0..n {
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
            let outs = f.coders.iter().fold(0u64, |a, c| a.saturating_add(c.outs));
            for _ in 0..outs {
                f.unpack_sizes.push(self.number()?);
            }
        }
        children.push(self.item("kCodersUnPackSize", at));
        loop {
            match self.byte()? {
                0x00 => break,
                0x0a => children.push(self.digests(n)?),
                _ => return Err("unexpected property in unpack info"),
            }
        }
        let mut item = self
            .item("kUnPackInfo", start)
            .with_summary(count(n, "folder", "folders"));
        item.children = children;
        Ok(item)
    }

    fn substreams(&mut self, s: &mut Streams) -> P<Item> {
        let start = self.at.saturating_sub(1);
        let mut children = Vec::new();
        let mut kind = self.byte()?;
        if kind == 0x0d {
            let at = self.at.saturating_sub(1);
            for f in &mut s.folders {
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
                    let n = s
                        .folders
                        .iter()
                        .fold(0u64, |a, f| a.saturating_add(f.streams));
                    children.push(self.digests(n)?);
                }
                _ => return Err("unexpected property in substreams info"),
            }
            kind = self.byte()?;
        }
        let mut item = self
            .item("kSubStreamsInfo", start)
            .with_summary(count(total, "stream", "streams"));
        item.children = children;
        Ok(item)
    }

    fn streams_info(&mut self, s: &mut Streams) -> P<Vec<Item>> {
        let mut items = Vec::new();
        let mut saw_substreams = false;
        loop {
            match self.byte()? {
                0x00 => break,
                0x06 => items.push(self.pack_info(s)?),
                0x07 => items.push(self.unpack_info(s)?),
                0x08 => {
                    saw_substreams = true;
                    items.push(self.substreams(s)?);
                }
                _ => return Err("unexpected property in streams info"),
            }
        }
        if !saw_substreams {
            s.sizes = s.folders.iter().map(Folder::unpack_size).collect();
        }
        Ok(items)
    }

    fn files_info(&mut self, a: &mut Archive) -> P<Item> {
        let start = self.at.saturating_sub(1);
        let n = self.count(1)?;
        let mut files: Vec<File> = (0..n).map(|_| File::default()).collect();
        let mut empty_stream = vec![false; to_usize(n)];
        let mut empty_file = Vec::new();
        let mut children = Vec::new();
        loop {
            let at = self.at;
            let kind = self.byte()?;
            if kind == 0 {
                break;
            }
            let size = self.number()?;
            let body = self.bytes(size)?.to_vec();
            let mut sub = Parser { data: &body, at: 0 };
            let mut summary = None;
            match kind {
                0x0e => {
                    empty_stream = sub.bits(n)?;
                    let empties = empty_stream.iter().filter(|&&e| e).count();
                    summary = Some(count(to_u64(empties), "empty stream", "empty streams"));
                }
                0x0f => {
                    let empties = to_u64(empty_stream.iter().filter(|&&e| e).count());
                    empty_file = sub.bits(empties)?;
                }
                0x11 => {
                    if sub.byte()? != 0 {
                        return Err("external names are not supported");
                    }
                    for f in &mut files {
                        let rest = body.get(sub.at..).unwrap_or_default();
                        let (name, len, _) = crate::text::utf16z(rest, Endian::Little);
                        f.name = name;
                        sub.at = sub.at.saturating_add(len);
                    }
                }
                0x12..=0x14 => {
                    let defined = sub.defined(n)?;
                    if sub.byte()? != 0 {
                        return Err("external times are not supported");
                    }
                    for (f, d) in files.iter_mut().zip(defined) {
                        if d {
                            let t = sub.u64()?;
                            if kind == 0x14 {
                                f.mtime = Some(t);
                            }
                        }
                    }
                }
                0x15 => {
                    let defined = sub.defined(n)?;
                    if sub.byte()? != 0 {
                        return Err("external attributes are not supported");
                    }
                    for (f, d) in files.iter_mut().zip(defined) {
                        if d {
                            f.attributes = Some(sub.u32()?);
                        }
                    }
                }
                _ => {}
            }
            let name = crate::value::lookup(PROPERTY, kind.into())
                .map_or_else(|| format!("Property {kind:#04x}"), str::to_owned);
            let mut item = self.item(name, at);
            item.summary = summary.or_else(|| Some(human_size(size)));
            children.push(item);
        }
        let mut empty = empty_file.into_iter();
        for (f, e) in files.iter_mut().zip(&empty_stream) {
            f.has_stream = !e;
            if *e {
                f.is_dir = !empty.next().unwrap_or(false);
            }
            if f.attributes.is_some_and(|a| a & 0x10 != 0) {
                f.is_dir = true;
            }
        }
        a.files = files;
        let mut item = self
            .item("kFilesInfo", start)
            .with_summary(count(n, "file", "files"));
        item.children = children;
        Ok(item)
    }

    fn header(&mut self) -> P<Archive> {
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
                            let children = self.streams_info(&mut extra)?;
                            let mut item = self.item("kAdditionalStreamsInfo", at);
                            item.children = children;
                            a.outline.push(item);
                        }
                        0x04 => {
                            let mut streams = Streams::default();
                            let children = self.streams_info(&mut streams)?;
                            a.streams = streams;
                            let mut item = self.item("kMainStreamsInfo", at);
                            item.children = children;
                            a.outline.push(item);
                        }
                        0x05 => {
                            let item = self.files_info(&mut a)?;
                            a.outline.push(item);
                        }
                        _ => return Err("unexpected property in header"),
                    }
                }
            }
            0x17 => {
                a.encoded = true;
                let mut streams = Streams::default();
                let children = self.streams_info(&mut streams)?;
                a.streams = streams;
                let mut item = self.item("kEncodedHeader", 0);
                item.children = children;
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
            let children: Vec<Node> = self.children.iter().map(|c| c.node(base)).collect();
            node = node.lazy(emit_nodes, Arc::new(children));
        }
        node
    }
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
    /// Post-filters, in the order they are applied.
    post: Vec<Post>,
}

/// The decoding plan of `f`, or why it cannot be decoded. Only simple
/// chains of one-input, one-output coders are supported (not BCJ2): the
/// packed stream feeds a decompressor, whose output runs through filters.
fn plan(f: &Folder) -> std::result::Result<Plan, String> {
    let n = f.coders.len();
    let simple = f.packed == 1
        && n > 0
        && f.coders.iter().all(|c| c.ins == 1 && c.outs == 1)
        && f.binds.len() == n.saturating_sub(1);
    if !simple {
        return Err(f.methods());
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
    let last = coder(first).ok_or_else(|| f.methods())?;
    let size = f.unpack_sizes.get(to_usize(first)).copied().unwrap_or(0);
    let codec = match last.id.as_slice() {
        [0x00] => Codec::Stored,
        [0x21] => Codec::Lzma2 {
            dict: last
                .props
                .first()
                .and_then(|&p| crate::codec::lzma::lzma2_dict(p)),
        },
        [0x03, 0x01, 0x01] => {
            let props = last
                .props
                .first()
                .and_then(|&b| crate::codec::lzma::Props::from_byte(b).ok())
                .ok_or_else(|| "LZMA with invalid properties".to_owned())?;
            Codec::LzmaRaw {
                props,
                size: Some(to_usize(size)),
                dict: crate::bytes::u32_le(&last.props, 1),
            }
        }
        [0x04, 0x01, 0x08] => Codec::Deflate,
        [0x04, 0x02, 0x02] => Codec::Bzip2,
        [0x04, 0xf7, 0x11, 0x01] => Codec::Zstd,
        [0x04, 0xf7, 0x11, 0x04] => Codec::Lz4Frame,
        id => return Err(method_name(id)),
    };
    let mut post = Vec::new();
    for &i in order.get(1..).unwrap_or_default() {
        let c = coder(i).ok_or_else(|| f.methods())?;
        post.push(match c.id.as_slice() {
            [0x04] | [0x03, 0x03, 0x01, 0x03] if c.props.is_empty() => Post::X86,
            [0x07] | [0x03, 0x03, 0x05, 0x01] if c.props.is_empty() => Post::Arm,
            [0x0a] if c.props.iter().all(|&b| b == 0) => Post::Arm64,
            [0x03] => {
                Post::Delta(usize::from(c.props.first().copied().unwrap_or(0)).saturating_add(1))
            }
            id => return Err(method_name(id)),
        });
    }
    Ok(Plan { codec, size, post })
}

/// Folders larger than this are decoded on demand.
const LAZY_THRESHOLD: u64 = 1024 * 1024;

/// The decoded output of the folder packed at `span`: lazily decoded when
/// large and without post-filters, else decoded in full.
async fn folder_output(cx: &Cx, span: Span, plan: &Plan) -> Result<(Span, Option<Diagnostic>)> {
    if plan.post.is_empty() {
        if plan.codec == Codec::Stored {
            return Ok((span, None));
        }
        if plan.size > LAZY_THRESHOLD
            && plan.size <= span.len.saturating_mul(plan.codec.max_ratio())
        {
            let decoded = cx.decode_lazy(span, &plan.codec, plan.size)?;
            return Ok((decoded, None));
        }
        let decoded = decode_span(cx, span, &plan.codec, Some(plan.size)).await?;
        return Ok((decoded.span, decoded.error));
    }
    let origin = Origin {
        parent: span,
        transform: "7z coders",
    };
    if let Some(found) = cx.derived(origin) {
        return Ok((found.span, found.error));
    }
    let decoded = decode_span(cx, span, &plan.codec, Some(plan.size)).await?;
    let mut bytes = read_all(cx, decoded.span).await?;
    for post in &plan.post {
        post.apply(&mut bytes);
    }
    let out = cx.add_derived(origin, bytes, decoded.consumed, decoded.error)?;
    Ok((out.span, out.error))
}

/// Expander: decodes a folder and dissects `len` bytes at `offset` of its
/// output (a file, or the whole folder).
async fn folder_part(
    cx: Cx,
    (input, span, plan, offset, len): (Input, Span, Arc<Plan>, u64, u64),
) -> Result<()> {
    let (out, error) = folder_output(&cx, span, &plan).await?;
    if let Some(e) = error {
        cx.diag(e);
    }
    cx.annotate(format!("{:#x} bytes {}", len, plan.codec.verb()));
    dissect_or_data(cx, input.nested(out.sub(offset, len))).await
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
    if crc32(&data) != sh.next_crc {
        next_node = next_node.diag(Diagnostic::warning("next header CRC mismatch"));
    }
    let parsed = Parser { data: &data, at: 0 }.header();
    let archive = match parsed {
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
    let mut archive = Arc::new(archive);
    let mut pack_base = SIGNATURE_HEADER.saturating_add(archive.streams.pack_pos);
    // Where packed streams end and the (outer) next header starts.
    let data_end = next
        .offset
        .saturating_sub(file.offset.saturating_add(SIGNATURE_HEADER));
    let mut header = next;

    if archive.encoded {
        let methods: Vec<String> = archive
            .streams
            .folders
            .iter()
            .map(Folder::methods)
            .collect();
        let methods = methods.join(", ");
        let packed: u64 = archive
            .streams
            .pack_sizes
            .iter()
            .fold(0u64, |a, &s| a.saturating_add(s));
        let header_span = file.sub(pack_base, packed);
        let size = archive
            .streams
            .folders
            .first()
            .map_or(0, Folder::unpack_size);
        let summary = format!("{methods}, {} → {}", human_size(packed), human_size(size));
        let outline: Vec<Node> = archive.outline.iter().map(|i| i.node(next)).collect();
        match decode_header(&cx, &archive, file, pack_base).await {
            Ok((span, inner)) => {
                cx.emit(
                    Node::new("Encoded header")
                        .span(header_span)
                        .summary(summary)
                        .lazy(emit_nodes, Arc::new(outline)),
                );
                pack_base = SIGNATURE_HEADER.saturating_add(inner.streams.pack_pos);
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
                            .summary(human_size(data_len)),
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
                        .lazy(emit_nodes, Arc::new(outline)),
                );
                cx.annotate(format!(
                    "7-Zip archive, header compressed ({methods}), {} packed",
                    human_size(file.len)
                ));
                return Ok(());
            }
        }
    }

    let files = to_u64(archive.files.len());
    let methods: Vec<String> = {
        let mut m: Vec<String> = archive
            .streams
            .folders
            .iter()
            .map(Folder::methods)
            .collect();
        m.dedup();
        m
    };
    cx.emit(
        Node::new("Files")
            .span(header)
            .summary(count(files, "file", "files"))
            .lazy(list_files, (input, archive.clone(), pack_base)),
    );
    cx.emit(
        Node::new("Folders")
            .span(file.sub(SIGNATURE_HEADER, data_end))
            .summary(count(
                to_u64(archive.streams.folders.len()),
                "folder",
                "folders",
            ))
            .lazy(list_folders, (input, archive.clone(), pack_base)),
    );
    let outline: Vec<Node> = archive.outline.iter().map(|i| i.node(header)).collect();
    cx.emit(
        next_node
            .summary("kHeader")
            .lazy(emit_nodes, Arc::new(outline)),
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
    let span = folder_spans(outer, file, pack_base)
        .first()
        .copied()
        .ok_or_else(|| Diagnostic::malformed("encoded header without a packed stream"))?;
    let p = plan(folder)
        .map_err(|why| Diagnostic::unsupported(format!("{why} compression")).at(span))?;
    let (out, error) = folder_output(cx, span, &p).await?;
    if let Some(e) = error {
        return Err(e);
    }
    let bytes = read_all(cx, out).await?;
    match (Parser {
        data: &bytes,
        at: 0,
    })
    .header()
    {
        Ok(a) if !a.encoded => Ok((out, a)),
        Ok(_) => Err(Diagnostic::malformed("encoded header inside an encoded header").at(out)),
        Err(e) => Err(Diagnostic::malformed(e).at(out)),
    }
}

/// Spans of each folder's first packed stream.
fn folder_spans(archive: &Archive, file: Span, pack_base: u64) -> Vec<Span> {
    let mut out = Vec::new();
    let mut pack_index = 0usize;
    let mut offsets = Vec::new();
    let mut at = pack_base;
    for &s in &archive.streams.pack_sizes {
        offsets.push((at, s));
        at = at.saturating_add(s);
    }
    for f in &archive.streams.folders {
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

async fn list_folders(
    cx: Cx,
    (input, archive, pack_base): (Input, Arc<Archive>, u64),
) -> Result<()> {
    let spans = folder_spans(&archive, input.span, pack_base);
    cx.set_count(Count::Exact(to_u64(archive.streams.folders.len())));
    for (i, (f, span)) in archive.streams.folders.iter().zip(spans).enumerate() {
        let methods = f.methods();
        let mut children: Vec<Node> = f
            .coders
            .iter()
            .enumerate()
            .map(|(j, c)| {
                Node::new(format!("Coder {j}"))
                    .value(text(method_name(&c.id)))
                    .summary(format!("{} in, {} out", c.ins, c.outs))
            })
            .collect();
        children.push(
            Node::new("Unpacked size")
                .value(uint(f.unpack_size()))
                .summary(human_size(f.unpack_size())),
        );
        children.push(Node::new("Streams").value(uint(f.streams)));
        children.push(match plan(f) {
            Ok(p) if p.codec == Codec::Stored && p.post.is_empty() => {
                embedded("Data", input.nested(span))
            }
            Ok(p) => {
                let size = f.unpack_size();
                Node::new("Data")
                    .span(span)
                    .lazy(folder_part, (input, span, Arc::new(p), 0, size))
            }
            Err(why) => unsupported("Data", span, &why),
        });
        cx.push(
            Node::new(format!("Folder {i}"))
                .span(span)
                .summary(format!(
                    "{methods}, {} → {}, {}",
                    human_size(span.len),
                    human_size(f.unpack_size()),
                    count(f.streams, "stream", "streams")
                ))
                .lazy(emit_nodes, Arc::new(children)),
        )
        .await;
    }
    Ok(())
}

async fn list_files(cx: Cx, (input, archive, pack_base): (Input, Arc<Archive>, u64)) -> Result<()> {
    let file = input.span;
    cx.set_count(Count::Exact(to_u64(archive.files.len())));
    let spans = folder_spans(&archive, file, pack_base);
    // Walk files and substreams together.
    let mut folder = 0usize;
    let mut in_folder = 0u64;
    let mut stream = 0usize;
    let mut offset_in_folder = 0u64;
    for f in archive.files.iter() {
        let mut node = Node::new(f.name.clone());
        let mut children = Vec::new();
        if let Some(t) = f.mtime {
            children.push(Node::new("Modification time").value(Value::Timestamp {
                unix_seconds: crate::text::filetime_to_unix(t),
            }));
        }
        if let Some(a) = f.attributes {
            let mut attr = Node::new("Attributes").value(hex(a.into()));
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
                folder = folder.saturating_add(1);
                in_folder = 0;
                offset_in_folder = 0;
            }
            let size = archive.streams.sizes.get(stream).copied().unwrap_or(0);
            let fo = archive.streams.folders.get(folder);
            let span = spans.get(folder).copied().unwrap_or(file.sub(0, 0));
            children.push(
                Node::new("Size")
                    .value(uint(size))
                    .summary(human_size(size)),
            );
            children.push(Node::new("Folder").value(uint(to_u64(folder))));
            let methods = fo.map(Folder::methods).unwrap_or_default();
            let content_node = match fo.map(plan) {
                Some(Ok(p)) if p.codec == Codec::Stored && p.post.is_empty() => {
                    let s = span.sub(offset_in_folder, size);
                    node = node.span(s);
                    embedded("Content", input.nested(s))
                }
                Some(Ok(p)) => {
                    node = node.span(span);
                    let mut c = Node::new("Content").span(span).lazy(
                        folder_part,
                        (input, span, Arc::new(p), offset_in_folder, size),
                    );
                    if fo.is_some_and(|f| f.streams > 1) {
                        c = c.summary(format!(
                            "{methods}, in a {} solid block",
                            human_size(fo.map_or(0, Folder::unpack_size))
                        ));
                    }
                    c
                }
                Some(Err(why)) => {
                    node = node.span(span);
                    unsupported("Content", span, &why).summary(format!(
                        "{methods}, in a {} solid block",
                        human_size(fo.map_or(0, Folder::unpack_size))
                    ))
                }
                None => {
                    node = node.span(span);
                    unsupported("Content", span, &methods).summary(format!(
                        "{methods}, in a {} solid block",
                        human_size(fo.map_or(0, Folder::unpack_size))
                    ))
                }
            };
            children.push(content_node);
            node = node.summary(human_size(size));
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
