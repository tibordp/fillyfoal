//! Optical-disc and console-disc image containers: MAME CHD, Nero NRG,
//! Alcohol MDS, DiscJuggler CDI, CloneCD CCD, GDI, ECM, CSO/ZSO,
//! DAX, ISZ, DAA, and the GameCube/Wii wrappers (WBFS, GCZ, WIA/RVZ, TGC,
//! CISO).

use super::util::{clean, is_ascii_text, lines};
use crate::bytes::{u16_le, u32_be, u32_le, u64_be, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::size;
use crate::formats::util::fmt::{fourcc, plural};
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Codec, Head, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// MAME CHD (compressed hunks of data)

declare_format!(pub CHD = "chd", "MAME compressed hunks of data (CHD)", ["chd"],
    "application/x-mame-chd", Probe::Magic(&[(0, b"MComprHD")]), chd);

const CHD_FLAGS: FlagTable = &[flag(1, "HAS_PARENT"), flag(2, "ALLOWS_WRITES")];
const CHD_V4_CODECS: EnumTable = &[(0, "none"), (1, "zlib"), (2, "zlib+"), (3, "A/V")];
const CHD_MAP_TYPES: EnumTable = &[
    (0, "invalid"),
    (1, "compressed"),
    (2, "uncompressed"),
    (3, "mini (8 bytes inline)"),
    (4, "copy of another hunk"),
    (5, "copy from parent"),
    (6, "compressed (second codec)"),
];
const CHD_META: EnumTable = &[
    (0x4744_4444, "hard disk geometry (GDDD)"),
    (0x4944_4e54, "hard disk identify data (IDNT)"),
    (0x4b45_5920, "hard disk key (KEY)"),
    (0x4349_5320, "PCMCIA CIS (CIS)"),
    (0x4348_4344, "CD-ROM TOC (CHCD)"),
    (0x4348_5452, "CD-ROM track (CHTR)"),
    (0x4348_5432, "CD-ROM track v2 (CHT2)"),
    (0x4348_4744, "GD-ROM (CHGD)"),
    (0x4348_4754, "GD-ROM track (CHGT)"),
    (0x4456_4420, "DVD (DVD)"),
    (0x4156_4156, "A/V metadata (AVAV)"),
    (0x4156_4c44, "laserdisc metadata (AVLD)"),
];

/// What we need from any CHD header version.
#[derive(Clone, Copy, Debug, Default)]
struct ChdInfo {
    version: u32,
    logical: u64,
    hunk_bytes: u64,
    hunks: u64,
    map: u64,
    meta: u64,
    compressed_map: bool,
    /// v5: bytes per unit and the four compressors' FourCCs.
    unit_bytes: u64,
    codecs: [u32; 4],
}

fn chd_header(f: &mut Fields<'_>, _: &()) -> Result<(ChdInfo, String)> {
    f.ascii("Magic", 8).emit()?;
    let header_len = u64::from(f.u32("Header length").emit()?);
    let version = f.u32("Version").emit()?;
    let mut info = ChdInfo {
        version,
        ..ChdInfo::default()
    };
    let codecs;
    match version {
        5 => {
            let mut names = Vec::new();
            for (slot, name) in [
                "Compressor 0",
                "Compressor 1",
                "Compressor 2",
                "Compressor 3",
            ]
            .into_iter()
            .enumerate()
            {
                let c = f
                    .u32(name)
                    .with(|&v, n| {
                        n.value(text(if v == 0 {
                            "none".to_owned()
                        } else {
                            fourcc(&u32::to_be_bytes(v))
                        }))
                    })
                    .emit()?;
                if let Some(codec) = info.codecs.get_mut(slot) {
                    *codec = c;
                }
                if c != 0 {
                    names.push(fourcc(&u32::to_be_bytes(c)));
                }
            }
            info.compressed_map = !names.is_empty();
            codecs = if names.is_empty() {
                "uncompressed".to_owned()
            } else {
                names.join("/")
            };
            info.logical = f.u64("Logical size").emit()?;
            info.map = f.u64("Map offset").hex().emit()?;
            info.meta = f.u64("Metadata offset").hex().emit()?;
            info.hunk_bytes = f.u32("Hunk size").emit()?.into();
            info.unit_bytes = f.u32("Unit size").emit()?.into();
            f.bytes("Raw SHA-1", 20).emit()?;
            f.bytes("SHA-1", 20).emit()?;
            f.bytes("Parent SHA-1", 20).emit()?;
            info.hunks = info.logical.div_ceil(info.hunk_bytes.max(1));
        }
        3 | 4 => {
            f.u32("Flags").flags(CHD_FLAGS).emit()?;
            let c = f.u32("Compression").enumeration(CHD_V4_CODECS).emit()?;
            codecs = lookup(CHD_V4_CODECS, c.into())
                .unwrap_or("unknown")
                .to_owned();
            info.hunks = f.u32("Total hunks").emit()?.into();
            info.logical = f.u64("Logical size").emit()?;
            info.meta = f.u64("Metadata offset").hex().emit()?;
            if version == 3 {
                f.bytes("MD5", 16).emit()?;
                f.bytes("Parent MD5", 16).emit()?;
            }
            info.hunk_bytes = f.u32("Hunk size").emit()?.into();
            f.bytes("SHA-1", 20).emit()?;
            f.bytes("Parent SHA-1", 20).emit()?;
            if version == 4 {
                f.bytes("Raw SHA-1", 20).emit()?;
            }
            info.map = header_len;
        }
        1 | 2 => {
            f.u32("Flags").flags(CHD_FLAGS).emit()?;
            let c = f.u32("Compression").enumeration(CHD_V4_CODECS).emit()?;
            codecs = lookup(CHD_V4_CODECS, c.into())
                .unwrap_or("unknown")
                .to_owned();
            let sectors = f.u32("Hunk size (sectors)").emit()?;
            info.hunks = f.u32("Total hunks").emit()?.into();
            f.u32("Cylinders").emit()?;
            f.u32("Heads").emit()?;
            f.u32("Sectors per track").emit()?;
            f.bytes("MD5", 16).emit()?;
            f.bytes("Parent MD5", 16).emit()?;
            let sector = if version == 2 {
                u64::from(f.u32("Sector size").emit()?)
            } else {
                512
            };
            info.hunk_bytes = u64::from(sectors).saturating_mul(sector);
            info.logical = info.hunk_bytes.saturating_mul(info.hunks);
            info.map = header_len;
        }
        _ => return Err(Diagnostic::unsupported(format!("CHD version {version}"))),
    }
    Ok((info, codecs))
}

async fn chd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(8, 8)).await?;
    let header_len = u64::from(u32_be(&head, 0).unwrap_or(0)).clamp(16, 1024);
    let span = file.sub(0, header_len);
    let (info, codecs) = crate::fields::parse(&cx, span, BE, &(), chd_header).await?;
    cx.emit(
        crate::fields::struct_node("Header", span, BE, (), chd_header)
            .summary(format!("version {}", info.version)),
    );
    // Metadata chain.
    let mut kinds = Vec::new();
    let mut entries = Vec::new();
    let mut next = info.meta;
    while next != 0 && entries.len() < 1000 {
        if entries.contains(&next) {
            cx.diag(Diagnostic::malformed("metadata chain loops"));
            break;
        }
        let Ok(raw) = cx.read(file.sub(next, 16)).await else {
            break;
        };
        entries.push(next);
        let tag = u32_be(&raw, 0).unwrap_or(0);
        let kind = match &fourcc(&u32::to_be_bytes(tag))[..] {
            "GDDD" | "IDNT" => "hard disk",
            "CHCD" | "CHTR" | "CHT2" => "CD-ROM",
            "CHGD" | "CHGT" => "GD-ROM",
            "DVD " => "DVD",
            "AVAV" | "AVLD" => "A/V",
            _ => "",
        };
        if !kind.is_empty() && !kinds.contains(&kind) {
            kinds.push(kind);
        }
        next = u64_be(&raw, 8).unwrap_or(0);
    }
    if !entries.is_empty() {
        cx.emit(
            Node::new("Metadata")
                .span(file.sub(info.meta, 16))
                .summary(plural(entries.len(), "entry"))
                .lazy(chd_metadata, (file, entries.clone())),
        );
    }
    let map_entry: u64 = match info.version {
        1 | 2 => 8,
        3 | 4 => 16,
        _ => 4,
    };
    if info.version == 5 && info.compressed_map && info.map != 0 {
        let raw = cx.read(file.sub(info.map, 4)).await?;
        let packed = u64::from(u32_be(&raw, 0).unwrap_or(0));
        let map = file.sub(info.map, packed.saturating_add(16));
        cx.emit(
            Node::new("Hunk map (compressed)")
                .span(map)
                .summary(format!("{} hunks", info.hunks))
                .lazy(chd_v5_map, (input, map, info)),
        );
    } else if info.map != 0 {
        let map = file.sub(info.map, info.hunks.saturating_mul(map_entry));
        cx.emit(
            Node::new("Hunk map")
                .span(map)
                .summary(format!("{} hunks", info.hunks))
                .lazy(chd_map, (input, map, info.version, info.hunk_bytes)),
        );
    }
    cx.annotate(format!(
        "CHD v{}, {}, {} in {} hunks of {}, {codecs}{}",
        info.version,
        if kinds.is_empty() {
            "raw data".to_owned()
        } else {
            kinds.join(" + ")
        },
        size(info.logical),
        info.hunks,
        size(info.hunk_bytes),
        if entries.is_empty() {
            String::new()
        } else {
            format!(", {} metadata entries", entries.len())
        }
    ));
    Ok(())
}

async fn chd_metadata(cx: Cx, (file, entries): (Span, Vec<u64>)) -> Result<()> {
    cx.set_count(Count::Exact(crate::bytes::to_u64(entries.len())));
    for at in entries {
        let raw = cx.read(file.sub(at, 16)).await?;
        let tag = u32_be(&raw, 0).unwrap_or(0);
        let flags_len = u32_be(&raw, 4).unwrap_or(0);
        let len = u64::from(flags_len & 0x00ff_ffff);
        let data = file.sub(at.saturating_add(16), len);
        let bytes = cx.read_avail(data.sub(0, 1024)).await?;
        let printable = bytes.split(|&b| b == 0).next().unwrap_or_default();
        let mut node = Node::new(fourcc(&u32::to_be_bytes(tag)))
            .span(file.sub(at, len.saturating_add(16)))
            .value(Value::Enum {
                raw: tag.into(),
                bits: 32,
                name: lookup(CHD_META, tag.into()).map(Into::into),
            });
        if !printable.is_empty() && is_ascii_text(printable) {
            node = node.summary(String::from_utf8_lossy(printable).into_owned());
        } else {
            node = node.summary(format!("{len} bytes"));
        }
        if flags_len >> 24 & 1 != 0 {
            node = node.desc("Checksummed (included in the SHA-1)");
        }
        cx.push(node.target(data)).await;
    }
    Ok(())
}

fn chd_v5_map_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Compressed map length").emit()?;
    super::util::uint_be(f, "First block offset", 6)?;
    f.u16("Map CRC-16").hex().emit()?;
    f.u8("Bits for compressed length").emit()?;
    f.u8("Bits for self references").emit()?;
    f.u8("Bits for parent references").emit()?;
    f.u8("Reserved").emit()?;
    Ok(())
}

async fn chd_v5_map(cx: Cx, (input, map, info): (Input, Span, ChdInfo)) -> Result<()> {
    cx.emit(crate::fields::struct_node(
        "Map header",
        map.sub(0, 16),
        BE,
        (),
        chd_v5_map_header,
    ));
    cx.emit(
        Node::new("Hunks")
            .span(map.tail(16))
            .summary(format!(
                "{} hunks, Huffman-coded types then bit-packed fields",
                info.hunks
            ))
            .lazy(chd_v5_hunks, (input, map, info)),
    );
    Ok(())
}

// The v5 map's hunk types (MAME `chd.cpp`): four codecs, uncompressed,
// a copy of another hunk, a range of the parent; then pseudo-types that
// only occur in the compressed map.
const V5_NONE: u32 = 4;
const V5_SELF: u32 = 5;
const V5_PARENT: u32 = 6;
const V5_RLE_SMALL: u32 = 7;
const V5_RLE_LARGE: u32 = 8;
const V5_SELF_0: u32 = 9;
const V5_SELF_1: u32 = 10;
const V5_PARENT_SELF: u32 = 11;
const V5_PARENT_0: u32 = 12;
const V5_PARENT_1: u32 = 13;

/// An MSB-first bit reader that reads zeros past the end, like MAME's
/// `bitstream_in` (which then reports an overflow).
struct Bits<'a> {
    data: &'a [u8],
    at: u64,
}

impl Bits<'_> {
    fn peek(&self, n: u32) -> u32 {
        let mut v = 0u32;
        for i in 0..u64::from(n.min(32)) {
            let bit = self.at.saturating_add(i);
            let byte = self
                .data
                .get(crate::bytes::to_usize(bit / 8))
                .copied()
                .unwrap_or(0);
            let shift = 7u64.saturating_sub(bit % 8);
            v = (v << 1) | u32::from((byte >> shift) & 1);
        }
        v
    }

    fn read(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.at = self.at.saturating_add(n.into());
        v
    }

    fn overflow(&self) -> bool {
        self.at > crate::bytes::to_u64(self.data.len()).saturating_mul(8)
    }
}

/// The 16-symbol, 8-bit-maximum canonical Huffman code the map's types
/// use, as a 256-entry lookup of (symbol, length).
struct Huffman([(u8, u8); 256]);

impl Huffman {
    /// MAME `huffman_context_base::import_tree_rle` with 16 codes of at
    /// most 8 bits (4-bit length fields; 1 escapes a literal 1 or a repeat).
    fn import(bits: &mut Bits<'_>) -> Result<Self> {
        let bad = || Diagnostic::malformed("CHD map: bad Huffman tree");
        let mut lens = [0u8; 16];
        let mut cur = 0usize;
        let put = |lens: &mut [u8; 16], len: u32, cur: &mut usize| -> Result<()> {
            let slot = lens.get_mut(*cur).ok_or_else(bad)?;
            *slot = u8::try_from(len).map_err(|_| bad())?;
            *cur = cur.saturating_add(1);
            Ok(())
        };
        while cur < 16 {
            let len = bits.read(4);
            if len != 1 {
                put(&mut lens, len, &mut cur)?;
                continue;
            }
            let len = bits.read(4);
            if len == 1 {
                put(&mut lens, 1, &mut cur)?;
            } else {
                let repeat = bits.read(4).saturating_add(3);
                for _ in 0..repeat {
                    put(&mut lens, len, &mut cur)?;
                }
            }
        }
        // Canonical codes, longest first (assign_canonical_codes).
        let mut start = [0u32; 33];
        for &len in &lens {
            if len > 8 {
                return Err(bad());
            }
            if let Some(n) = start.get_mut(usize::from(len)) {
                *n = n.saturating_add(1);
            }
        }
        let mut next = 0u32;
        for len in (1..=32usize).rev() {
            let count = start.get(len).copied().unwrap_or(0);
            let sum = next.saturating_add(count);
            if len != 1 && sum % 2 != 0 {
                return Err(bad());
            }
            if let Some(n) = start.get_mut(len) {
                *n = next;
            }
            next = sum >> 1;
        }
        let mut table = [(0u8, 0u8); 256];
        for (symbol, &len) in lens.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let slot = start.get_mut(usize::from(len)).ok_or_else(bad)?;
            let code = *slot;
            *slot = code.saturating_add(1);
            let shift = 8u32.saturating_sub(len.into());
            let first =
                usize::try_from(code.checked_shl(shift).ok_or_else(bad)?).map_err(|_| bad())?;
            let last = usize::try_from(code.saturating_add(1).checked_shl(shift).ok_or_else(bad)?)
                .map_err(|_| bad())?;
            for entry in table.get_mut(first..last).ok_or_else(bad)? {
                *entry = (u8::try_from(symbol).unwrap_or(0), len);
            }
        }
        Ok(Huffman(table))
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u32> {
        let (symbol, len) = self
            .0
            .get(crate::bytes::to_usize(bits.peek(8).into()))
            .copied()
            .unwrap_or((0, 0));
        if len == 0 {
            return Err(Diagnostic::malformed("CHD map: invalid Huffman code"));
        }
        bits.read(len.into());
        Ok(symbol.into())
    }
}

/// The type sequence's reader and run-length state (MAME's `lastcomp` and
/// `repcount`).
#[derive(Clone, Copy, Default)]
struct V5Types {
    at: u64,
    last: u32,
    repeat: u32,
}

impl V5Types {
    fn next(&mut self, data: &[u8], huffman: &Huffman) -> Result<u32> {
        if self.repeat > 0 {
            self.repeat = self.repeat.saturating_sub(1);
            return Ok(self.last);
        }
        let mut bits = Bits { data, at: self.at };
        let value = huffman.decode(&mut bits)?;
        // A run repeats the last type for this hunk and `repcount` more.
        match value {
            V5_RLE_SMALL => self.repeat = 2u32.saturating_add(huffman.decode(&mut bits)?),
            V5_RLE_LARGE => {
                let high = huffman.decode(&mut bits)?;
                let low = huffman.decode(&mut bits)?;
                self.repeat = 18u32.saturating_add(high << 4).saturating_add(low);
            }
            v => self.last = v,
        }
        self.at = bits.at;
        Ok(self.last)
    }
}

/// Where a resumed walk over the hunks picks up.
#[derive(Clone, Copy, Default)]
struct V5Walk {
    hunk: u64,
    types: V5Types,
    fields: u64,
    offset: u64,
    last_self: u64,
    last_parent: u64,
    crc: u64,
}

/// MAME's `crc16_creator`: CRC-16/CCITT-FALSE.
const CRC16_CCITT_FALSE: crate::codec::crc::Crc =
    crate::codec::crc::Crc::new(16, 0x1021, 0xffff, false, 0);

/// MAME `chd_file::decompress_v5_map`, one hunk per child.
async fn chd_v5_hunks(cx: Cx, (input, map, info): (Input, Span, ChdInfo)) -> Result<()> {
    let file = input.span;
    let header = cx.read(map.sub(0, 16)).await?;
    let first = header
        .get(4..10)
        .unwrap_or_default()
        .iter()
        .fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let expected_crc = crate::bytes::u16_be(&header, 10).unwrap_or(0);
    let length_bits = u32::from(header.get(12).copied().unwrap_or(0));
    let self_bits = u32::from(header.get(13).copied().unwrap_or(0));
    let parent_bits = u32::from(header.get(14).copied().unwrap_or(0));
    let data = cx.read(map.tail(16)).await?;
    let mut tree = Bits { data: &data, at: 0 };
    let huffman = Huffman::import(&mut tree)?;
    let types_start = V5Types {
        at: tree.at,
        ..V5Types::default()
    };
    // The fields follow the whole type sequence: find where it ends, once.
    let fields_start = match cx.cached::<u64>(map, "chd-v5-fields") {
        Some(at) => *at,
        None => {
            let mut types = types_start;
            for i in 0..info.hunks {
                if i % 4096 == 4095 {
                    cx.checkpoint().await;
                }
                types.next(&data, &huffman)?;
                // Each code covers at most 273 hunks, so types that run out
                // before the hunks do mean a cut or lying map.
                if (Bits {
                    data: &data,
                    at: types.at,
                })
                .overflow()
                {
                    return Err(Diagnostic::malformed(format!(
                        "CHD map: hunk types end after {i} of {} hunks",
                        info.hunks
                    )));
                }
            }
            cx.cache(map, "chd-v5-fields", std::sync::Arc::new(types.at));
            types.at
        }
    };
    cx.set_count(Count::Exact(info.hunks));
    let mut w = cx.resume::<V5Walk>().unwrap_or(V5Walk {
        types: types_start,
        fields: fields_start,
        offset: first,
        crc: CRC16_CCITT_FALSE.init(),
        ..V5Walk::default()
    });
    let units_per_hunk = info.hunk_bytes.checked_div(info.unit_bytes).unwrap_or(0);
    while w.hunk < info.hunks {
        let mark = w;
        cx.mark(move || mark);
        let raw = w.types.next(&data, &huffman)?;
        let mut bits = Bits {
            data: &data,
            at: w.fields,
        };
        let mut kind = raw;
        let mut offset = w.offset;
        let mut length = 0u64;
        let mut crc = 0u16;
        match raw {
            0..=3 => {
                length = bits.read(length_bits).into();
                w.offset = w.offset.saturating_add(length);
                crc = u16::try_from(bits.read(16)).unwrap_or(0);
            }
            V5_NONE => {
                length = info.hunk_bytes;
                w.offset = w.offset.saturating_add(length);
                crc = u16::try_from(bits.read(16)).unwrap_or(0);
            }
            V5_SELF => {
                offset = bits.read(self_bits).into();
                w.last_self = offset;
            }
            V5_PARENT => {
                offset = bits.read(parent_bits).into();
                w.last_parent = offset;
            }
            V5_SELF_0 | V5_SELF_1 => {
                if raw == V5_SELF_1 {
                    w.last_self = w.last_self.saturating_add(1);
                }
                kind = V5_SELF;
                offset = w.last_self;
            }
            V5_PARENT_SELF => {
                kind = V5_PARENT;
                offset = w.hunk.saturating_mul(units_per_hunk);
                w.last_parent = offset;
            }
            V5_PARENT_0 | V5_PARENT_1 => {
                if raw == V5_PARENT_1 {
                    w.last_parent = w.last_parent.saturating_add(units_per_hunk);
                }
                kind = V5_PARENT;
                offset = w.last_parent;
            }
            _ => {
                return Err(Diagnostic::malformed(format!(
                    "CHD map: hunk {} has type {raw}",
                    w.hunk
                )));
            }
        }
        w.fields = bits.at;
        // The CRC covers the 12-byte entries MAME decodes the map into:
        // type, 24-bit length, 48-bit offset, CRC-16, big-endian.
        let mut entry = [0u8; 12];
        let mut put = |at: usize, value: u64, width: usize| {
            for k in 0..width {
                if let Some(b) = entry.get_mut(at.saturating_add(k)) {
                    let shift = width.saturating_sub(1).saturating_sub(k).saturating_mul(8);
                    *b = value
                        .checked_shr(u32::try_from(shift).unwrap_or(u32::MAX))
                        .unwrap_or(0) as u8;
                }
            }
        };
        put(0, kind.into(), 1);
        put(1, length, 3);
        put(4, offset, 6);
        put(10, crc.into(), 2);
        w.crc = CRC16_CCITT_FALSE.update(w.crc, &entry);
        let codec = |slot: u32| {
            let c = info
                .codecs
                .get(crate::bytes::to_usize(slot.into()))
                .copied()
                .unwrap_or(0);
            fourcc(&c.to_be_bytes())
        };
        let (summary, target) = match kind {
            0..=3 => (
                format!(
                    "{}, {length} bytes at {offset:#x}, CRC-16 {crc:#06x}",
                    codec(kind)
                ),
                Some(file.sub(offset, length)),
            ),
            V5_NONE => (
                format!("uncompressed at {offset:#x}, CRC-16 {crc:#06x}"),
                Some(file.sub(offset, length)),
            ),
            V5_SELF => (format!("same as hunk {offset}"), None),
            _ => (format!("parent's unit {offset}"), None),
        };
        let name = format!("Hunk {}", w.hunk);
        let mut node = match (kind, target) {
            (0..=3, Some(span)) => chd_hunk(input, name, span, &codec(kind), info.hunk_bytes),
            (V5_NONE, Some(span)) => embedded(name, input.nested(span)),
            _ => Node::new(name),
        }
        .value(hex(offset, 64))
        .summary(summary);
        if let Some(target) = target {
            node = node.target(target);
        }
        w.hunk = w.hunk.saturating_add(1);
        if w.hunk == info.hunks {
            let crc = CRC16_CCITT_FALSE.finish(w.crc);
            if crc != u64::from(expected_crc) {
                node = node.diag(Diagnostic::malformed(format!(
                    "map CRC-16 {crc:#06x}, header says {expected_crc:#06x}"
                )));
            }
            if bits.overflow() {
                node = node.diag(Diagnostic::malformed("map ends early"));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn chd_map(cx: Cx, (input, map, version, hunk_bytes): (Input, Span, u32, u64)) -> Result<()> {
    let file = input.span;
    let entry: u64 = match version {
        1 | 2 => 8,
        3 | 4 => 16,
        _ => 4,
    };
    let count = map.len.checked_div(entry).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = map.sub(i.saturating_mul(entry), entry);
        let raw = cx.read(span).await?;
        let mut decode = None;
        let (summary, value, target) = match version {
            1 | 2 => {
                let v = u64_be(&raw, 0).unwrap_or(0);
                let offset = v & 0x0fff_ffff_ffff;
                let len = v >> 44;
                (
                    format!("{len} bytes at {offset:#x}"),
                    offset,
                    file.sub(offset, len),
                )
            }
            3 | 4 => {
                let offset = u64_be(&raw, 0).unwrap_or(0);
                let len = u64::from(crate::bytes::u16_be(&raw, 12).unwrap_or(0))
                    | u64::from(raw.get(14).copied().unwrap_or(0)) << 16;
                let kind = raw.get(15).copied().unwrap_or(0);
                let name = lookup(CHD_MAP_TYPES, u64::from(kind & 0x0f)).unwrap_or("unknown");
                let crc = u32_be(&raw, 8).unwrap_or(0);
                decode = Some(kind & 0x0f);
                match kind & 0x0f {
                    1 | 2 | 6 => (
                        format!("{name}, {len} bytes at {offset:#x}, CRC {crc:#010x}"),
                        offset,
                        file.sub(offset, len),
                    ),
                    3 => (format!("{name}: {offset:016x}"), offset, file.sub(0, 0)),
                    _ => (format!("{name} {offset}"), offset, file.sub(0, 0)),
                }
            }
            _ => {
                let block = u64::from(u32_be(&raw, 0).unwrap_or(0));
                let offset = block.saturating_mul(hunk_bytes);
                if block == 0 {
                    ("not present (reads as zeros)".to_owned(), 0, file.sub(0, 0))
                } else {
                    (
                        format!("stored at {offset:#x}"),
                        offset,
                        file.sub(offset, hunk_bytes),
                    )
                }
            }
        };
        let name = format!("Hunk {i}");
        let mut node = match decode {
            // v3/v4 "zlib" hunks are raw deflate streams (MAME chd.cpp).
            Some(1) if target.len > 0 => {
                content(name, input, target, Codec::Deflate, Some(hunk_bytes))
            }
            Some(2) if target.len > 0 => embedded(name, input.nested(target)),
            _ => Node::new(name),
        }
        .span(span)
        .value(hex(value, 64))
        .summary(summary);
        if target.len > 0 {
            node = node.target(target);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// A v5 hunk compressed with `codec` (MAME `chdcodec.cpp`), decoded on
/// expansion: zlib (raw deflate), LZMA (raw, MAME's properties) and the CD
/// codecs built on them; Huffman and FLAC hunks are not decoded.
fn chd_hunk(input: Input, name: String, span: Span, codec: &str, hunk_bytes: u64) -> Node {
    match codec {
        "zlib" => content(name, input, span, Codec::Deflate, Some(hunk_bytes)),
        "lzma" => content(name, input, span, chd_lzma(hunk_bytes), Some(hunk_bytes)),
        "cdzl" | "cdlz" => Node::new(name)
            .span(span)
            .lazy(chd_cd_hunk, (input, span, hunk_bytes, codec == "cdlz")),
        _ => Node::new(name)
            .span(span)
            .diag(Diagnostic::unsupported(format!("CHD {codec} hunk")).at(span)),
    }
}

/// MAME's LZMA hunks: raw LZMA (lc 3, lp 0, pb 2), with the dictionary
/// LzmaEncProps_Normalize picks for level 9 and a hunk-sized input.
fn chd_lzma(hunk_bytes: u64) -> Codec {
    let mut dict: u64 = 1 << 26;
    for i in 11..=30u32 {
        let two = 2u64 << i;
        let three = 3u64 << i;
        if hunk_bytes <= two {
            dict = two;
            break;
        }
        if hunk_bytes <= three {
            dict = three;
            break;
        }
    }
    Codec::LzmaRaw {
        props: crate::codec::lzma::Props {
            lc: 3,
            lp: 0,
            pb: 2,
        },
        size: usize::try_from(hunk_bytes).ok(),
        dict: u32::try_from(dict.min(1 << 26)).ok(),
    }
}

/// CD frames: 2352 bytes of sector data and 96 of subcode.
const CD_SECTOR: u64 = 2352;
const CD_SUBCODE: u64 = 96;
const CD_FRAME: u64 = CD_SECTOR + CD_SUBCODE;
/// Largest CD hunk rebuilt in memory.
const MAX_CD_HUNK: u64 = 1 << 20;

/// A `cdzl`/`cdlz` hunk (MAME `chd_cd_decompressor`): a bitmap of frames
/// whose sync header and ECC were dropped, the base stream's length, the
/// sector data (zlib or LZMA) and the subcode (zlib); the frames are
/// interleaved again and the dropped parts regenerated.
async fn chd_cd_hunk(
    cx: Cx,
    (input, span, hunk_bytes, lzma): (Input, Span, u64, bool),
) -> Result<()> {
    if hunk_bytes > MAX_CD_HUNK {
        return Err(Diagnostic::limit("CD hunk too large to rebuild").at(span));
    }
    let src = cx.read(span).await?;
    let frames = hunk_bytes / CD_FRAME;
    let ecc_bytes = frames.div_ceil(8);
    let length_bytes: u64 = if hunk_bytes < 65536 { 2 } else { 3 };
    let header = ecc_bytes.saturating_add(length_bytes);
    let at = |i: u64| {
        src.get(crate::bytes::to_usize(i))
            .copied()
            .map(u64::from)
            .unwrap_or(0)
    };
    let mut base_len = 0u64;
    for k in 0..length_bytes {
        base_len = (base_len << 8) | at(ecc_bytes.saturating_add(k));
    }
    let base = span.sub_exact(header, base_len)?;
    let sub = span.tail(header.saturating_add(base_len));
    let base_codec = if lzma {
        chd_lzma(frames.saturating_mul(CD_SECTOR))
    } else {
        Codec::Deflate
    };
    let sectors = crate::codec::decode_span(
        &cx,
        base,
        &base_codec,
        Some(frames.saturating_mul(CD_SECTOR)),
    )
    .await?;
    let subcode = crate::codec::decode_span(
        &cx,
        sub,
        &Codec::Deflate,
        Some(frames.saturating_mul(CD_SUBCODE)),
    )
    .await?;
    let sectors_data = cx.read(sectors.span).await?;
    let subcode_data = cx.read(subcode.span).await?;
    let mut out = Vec::with_capacity(crate::bytes::to_usize(hunk_bytes));
    for frame in 0..frames {
        let start = out.len();
        let s = crate::bytes::to_usize(frame.saturating_mul(CD_SECTOR));
        let mut sector = [0u8; 2352];
        if let Some(src) = sectors_data.get(s..s.saturating_add(2352)) {
            sector.copy_from_slice(src);
        }
        if at(frame / 8) & (1 << (frame % 8)) != 0 {
            if let Some(sync) = sector.get_mut(..12) {
                sync.copy_from_slice(&CD_SYNC);
            }
            ecc_generate(&mut sector);
        }
        out.extend_from_slice(&sector);
        let c = crate::bytes::to_usize(frame.saturating_mul(CD_SUBCODE));
        out.extend_from_slice(
            subcode_data
                .get(c..c.saturating_add(96))
                .unwrap_or(&[0; 96]),
        );
        out.resize(start.saturating_add(crate::bytes::to_usize(CD_FRAME)), 0);
        if frame % 64 == 63 {
            cx.checkpoint().await;
        }
    }
    out.resize(crate::bytes::to_usize(hunk_bytes), 0);
    let error = sectors.error.or(subcode.error);
    let rebuilt = cx.add_derived(
        crate::span::Origin {
            parent: span,
            transform: "CHD CD hunk",
        },
        out,
        span.len,
        error,
    )?;
    crate::formats::dissect_or_data(cx, input.nested(rebuilt.span)).await
}

const CD_SYNC: [u8; 12] = [
    0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0,
];

/// GF(2^8) tables of the CD-ROM ECC (polynomial 0x11d): multiply by 2,
/// and its "inverse" lookup (`b[i ^ f[i]] = i`).
struct EccTables {
    f: [u8; 256],
    b: [u8; 256],
}

impl EccTables {
    fn new() -> Self {
        let mut t = EccTables {
            f: [0; 256],
            b: [0; 256],
        };
        for i in 0..=255u8 {
            let j = (i << 1) ^ if i & 0x80 != 0 { 0x1d } else { 0 };
            if let Some(slot) = t.f.get_mut(usize::from(i)) {
                *slot = j;
            }
            if let Some(slot) = t.b.get_mut(usize::from(i ^ j)) {
                *slot = i;
            }
        }
        t
    }
}

/// Computes one ECC block (ECMA-130 P or Q parity) over the 2236 bytes
/// after the sync header: `major_count` pairs.
fn ecc_block(
    t: &EccTables,
    src: &[u8],
    (major_count, minor_count, mult, inc): (usize, usize, usize, usize),
) -> Vec<u8> {
    let (f, b) = (&t.f, &t.b);
    let size = major_count.saturating_mul(minor_count);
    let mut dest = vec![0u8; major_count.saturating_mul(2)];
    for major in 0..major_count {
        let mut index = (major >> 1).saturating_mul(mult).saturating_add(major & 1);
        let (mut a, mut x) = (0u8, 0u8);
        for _ in 0..minor_count {
            let t = src.get(index).copied().unwrap_or(0);
            index = index.saturating_add(inc);
            if index >= size {
                index = index.saturating_sub(size);
            }
            a ^= t;
            x ^= t;
            a = f.get(usize::from(a)).copied().unwrap_or(0);
        }
        let fa = f.get(usize::from(a)).copied().unwrap_or(0);
        a = b.get(usize::from(fa ^ x)).copied().unwrap_or(0);
        if let Some(d) = dest.get_mut(major) {
            *d = a;
        }
        if let Some(d) = dest.get_mut(major.saturating_add(major_count)) {
            *d = a ^ x;
        }
    }
    dest
}

/// Regenerates a sector's P and Q parity (MAME `ecc_generate`; in mode 2
/// the four header bytes count as zeros).
fn ecc_generate(sector: &mut [u8; 2352]) {
    let mode2 = sector.get(15) == Some(&2);
    let mut src = [0u8; 2236];
    if let Some(s) = sector.get(12..12 + 2236) {
        src.copy_from_slice(s);
    }
    if mode2 {
        src.get_mut(..4).into_iter().for_each(|h| h.fill(0));
    }
    // P: 86 columns of 24 bytes; it covers the first 2064 bytes.
    let tables = EccTables::new();
    let p = ecc_block(&tables, &src, (86, 24, 2, 86));
    if let Some(d) = src.get_mut(2064..2064 + 172) {
        d.copy_from_slice(&p);
    }
    // Q: 52 diagonals of 43 bytes over those and P.
    let q = ecc_block(&tables, &src, (52, 43, 86, 88));
    if let Some(d) = sector.get_mut(12 + 2064..12 + 2064 + 172) {
        d.copy_from_slice(&p);
    }
    if let Some(d) = sector.get_mut(12 + 2236..12 + 2236 + 104) {
        d.copy_from_slice(&q);
    }
}

// ---------------------------------------------------------------------------
// Nero NRG (footer at the end of the image)

fn nrg_probe(h: &Head<'_>) -> bool {
    let n = h.tail.len();
    h.tail.get(n.saturating_sub(12)..n.saturating_sub(8)) == Some(b"NER5")
        || h.tail.get(n.saturating_sub(8)..n.saturating_sub(4)) == Some(b"NERO")
}

declare_format!(pub NRG = "nrg", "Nero disc image", ["nrg"],
    "application/x-nrg", Probe::Custom(nrg_probe), nrg);

const NRG_CHUNKS: EnumTable = &[
    (0x4355_4558, "cue sheet (CUEX)"),
    (0x4355_4553, "cue sheet (CUES)"),
    (0x4441_4f58, "disc-at-once info (DAOX)"),
    (0x4441_4f49, "disc-at-once info (DAOI)"),
    (0x4344_5458, "CD-TEXT (CDTX)"),
    (0x4554_4e32, "track-at-once info (ETN2)"),
    (0x4554_4e46, "track-at-once info (ETNF)"),
    (0x5349_4e46, "session info (SINF)"),
    (0x4d54_5950, "media type (MTYP)"),
    (0x4449_4e46, "disc info (DINF)"),
    (0x544f_4354, "TOC type (TOCT)"),
    (0x5245_4c4f, "RELO"),
    (0x454e_4421, "end (END!)"),
];

const NRG_MODES: EnumTable = &[
    (0x00, "Mode 1 (2048)"),
    (0x02, "Mode 2 form 1 (2048)"),
    (0x03, "Mode 2 (2336)"),
    (0x05, "Mode 1 raw (2352)"),
    (0x06, "Mode 2 raw (2352)"),
    (0x07, "audio (2352)"),
    (0x0f, "Mode 1 raw + subchannel"),
    (0x10, "audio + subchannel"),
    (0x11, "Mode 2 raw + subchannel"),
];

async fn nrg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let tail = cx.read(file.sub(file.len.saturating_sub(12), 12)).await?;
    let (version, start) = if tail.get(0..4) == Some(b"NER5") {
        cx.emit(
            Node::new("Footer (NER5)")
                .span(file.tail(file.len.saturating_sub(12)))
                .value(hex(u64_be(&tail, 4).unwrap_or(0), 64))
                .desc("Offset of the chunk list"),
        );
        (2, u64_be(&tail, 4).unwrap_or(0))
    } else {
        cx.emit(
            Node::new("Footer (NERO)")
                .span(file.tail(file.len.saturating_sub(8)))
                .value(hex(u32_be(&tail, 8).unwrap_or(0), 32))
                .desc("Offset of the chunk list"),
        );
        (1, u64::from(u32_be(&tail, 8).unwrap_or(0)))
    };
    cx.emit(
        Node::new("Image data")
            .span(file.sub(0, start))
            .summary(size(start)),
    );
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(start);
    let (mut chunks, mut tracks, mut sessions) = (0u32, 0u64, 0u32);
    let mut media = None;
    while cur.remaining() >= 8 {
        let at = cur.pos();
        let id = cur.u32().await?;
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len);
        chunks = chunks.saturating_add(1);
        let tag = fourcc(&u32::to_be_bytes(id));
        let mut node = Node::new(tag.clone())
            .span(cur.since(at))
            .value(Value::Enum {
                raw: id.into(),
                bits: 32,
                name: lookup(NRG_CHUNKS, id.into()).map(Into::into),
            });
        match &tag[..] {
            "DAOX" | "DAOI" => {
                let wide = tag == "DAOX";
                let per = if wide { 42u64 } else { 30 };
                let n = data.len.saturating_sub(22).checked_div(per).unwrap_or(0);
                tracks = tracks.saturating_add(n);
                node = node.summary(plural(n, "track")).lazy(nrg_dao, (data, wide));
            }
            "ETN2" | "ETNF" => {
                let per = if tag == "ETN2" { 32u64 } else { 20 };
                let n = data.len.checked_div(per).unwrap_or(0);
                tracks = tracks.saturating_add(n);
                node = node.summary(plural(n, "track"));
            }
            "SINF" => {
                sessions = sessions.saturating_add(1);
                let raw = cx.read_avail(data.sub(0, 4)).await?;
                node = node.summary(format!(
                    "{} in session",
                    plural(u32_be(&raw, 0).unwrap_or(0), "track")
                ));
            }
            "MTYP" => {
                let raw = cx.read_avail(data.sub(0, 4)).await?;
                let m = u32_be(&raw, 0).unwrap_or(0);
                media = Some(m);
                node = node.summary(format!("{m:#x}"));
            }
            "CUEX" | "CUES" => {
                node = node
                    .summary(plural(data.len / 8, "entry"))
                    .lazy(nrg_cue, (data, tag == "CUEX"));
            }
            _ => {}
        }
        cx.push(node).await;
        if tag == "END!" {
            break;
        }
    }
    cx.annotate(format!(
        "Nero image (v{version}), {} of data, {sessions} session(s), {tracks} track(s), {chunks_chunk}{}",
        size(start),
        media.map_or_else(String::new, |m| format!(", media type {m:#x}")), chunks_chunk = plural(chunks, "chunk")
    ));
    Ok(())
}

async fn nrg_cue(cx: Cx, (data, wide): (Span, bool)) -> Result<()> {
    let count = data.len / 8;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = data.sub(i.saturating_mul(8), 8);
        let raw = cx.read(span).await?;
        let [mode, track, index, _] = [0usize, 1, 2, 3].map(|j| raw.get(j).copied().unwrap_or(0));
        let lba = if wide {
            format!("LBA {}", crate::bytes::i32_be(&raw, 4).unwrap_or(0))
        } else {
            let [m, s, f] = [5usize, 6, 7].map(|j| raw.get(j).copied().unwrap_or(0));
            format!("MSF {m:02x}:{s:02x}:{f:02x}")
        };
        cx.push(Node::new(format!("Entry {i}")).span(span).summary(format!(
            "track {track:02x} index {index:02x}, control/ADR {mode:#04x}, {lba}"
        )))
        .await;
    }
    Ok(())
}

async fn nrg_dao(cx: Cx, (data, wide): (Span, bool)) -> Result<()> {
    let head = cx.block(data.sub(0, 22)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Chunk size (repeated)").emit()?;
    f.ascii("UPC", 14).emit()?;
    f.u16("TOC type").hex().emit()?;
    f.u8("First track").emit()?;
    f.u8("Last track").emit()?;
    let per = if wide { 42u64 } else { 30 };
    let n = data.len.saturating_sub(22).checked_div(per).unwrap_or(0);
    for i in 0..n.min(99) {
        let span = data.sub(22u64.saturating_add(i.saturating_mul(per)), per);
        let raw = cx.read(span).await?;
        let sector = crate::bytes::u16_be(&raw, 12).unwrap_or(0);
        let mode = raw.get(14).copied().unwrap_or(0);
        let (start, end) = if wide {
            (u64_be(&raw, 26).unwrap_or(0), u64_be(&raw, 34).unwrap_or(0))
        } else {
            (
                u64::from(u32_be(&raw, 22).unwrap_or(0)),
                u64::from(u32_be(&raw, 26).unwrap_or(0)),
            )
        };
        let mode_name = lookup(NRG_MODES, mode.into()).unwrap_or("unknown mode");
        cx.emit(
            Node::new(format!("Track {}", i.saturating_add(1)))
                .span(span)
                .summary(format!(
                    "{mode_name}, {sector}-byte sectors, image {start:#x}..{end:#x}"
                )),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Alcohol 120% media descriptor (MDS)

declare_format!(pub MDS = "mds", "Alcohol 120% media descriptor", ["mds"],
    "application/x-mds", Probe::Magic(&[(0, b"MEDIA DESCRIPTOR")]), mds);

const MDS_MEDIUM: EnumTable = &[
    (0x00, "CD-ROM"),
    (0x01, "CD-R"),
    (0x02, "CD-RW"),
    (0x10, "DVD-ROM"),
    (0x12, "DVD-R"),
];
const MDS_TRACK_MODES: EnumTable = &[
    (0x00, "none"),
    (0xa9, "audio"),
    (0xaa, "Mode 1"),
    (0xab, "Mode 2"),
    (0xac, "Mode 2 form 1"),
    (0xad, "Mode 2 form 2"),
    (0xec, "Mode 2 form 1 (alt)"),
    (0xe9, "audio (alt)"),
    (0xea, "Mode 1 (alt)"),
];
const MDS_SUBCHANNEL: EnumTable = &[(0x00, "none"), (0x08, "PW interleaved (96 bytes)")];

record! {
    pub struct MdsHeader {
        signature: ascii[16] "Signature",
        major: u8 "Major version",
        minor: u8 "Minor version",
        medium: u16 "Medium type" .enumeration(MDS_MEDIUM),
        sessions: u16 "Sessions",
        _dummy: bytes[4] "Reserved",
        bca_len: u16 "BCA length",
        _dummy2: bytes[8] "Reserved",
        bca_offset: u32 "BCA offset" .hex(),
        _dummy3: bytes[24] "Reserved",
        structures_offset: u32 "Disc structures offset" .hex(),
        _dummy4: bytes[12] "Reserved",
        sessions_offset: u32 "Session blocks offset" .hex(),
        dpm_offset: u32 "DPM blocks offset" .hex(),
    }
}

record! {
    pub struct MdsSession {
        start: i32 "Session start sector",
        end: i32 "Session end sector",
        number: u16 "Session number",
        blocks: u8 "Number of blocks",
        non_track: u8 "Non-track blocks",
        first_track: u16 "First track",
        last_track: u16 "Last track",
        _dummy: u32 "Reserved",
        tracks_offset: u32 "Track blocks offset" .hex(),
    }
}

record! {
    pub struct MdsTrack {
        mode: u8 "Mode" .enumeration(MDS_TRACK_MODES),
        subchannel: u8 "Subchannel" .enumeration(MDS_SUBCHANNEL),
        adr_ctl: u8 "ADR/Control" .hex(),
        tno: u8 "Track number (TNO)",
        point: u8 "Point" .hex() .desc("Track number, or 0xA0/0xA1/0xA2 for lead-in entries"),
        _dummy: u32 "Reserved",
        min: u8 "Minute",
        sec: u8 "Second",
        frame: u8 "Frame",
        extra_offset: u32 "Extra block offset" .hex(),
        sector_size: u16 "Sector size",
        _dummy2: bytes[18] "Reserved",
        start_sector: u32 "Start sector",
        start_offset: u64 "Start offset in image" .hex(),
        files: u32 "Number of files",
        footer_offset: u32 "Footer offset" .hex(),
        _dummy3: bytes[24] "Reserved",
    }
}

async fn mds(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, MdsHeader::SIZE);
    let h: MdsHeader = read_record(&cx, span, LE).await?;
    cx.emit(MdsHeader::node("Header", span, LE));
    let mut tracks = 0u32;
    let mut image = None;
    for s in 0..u64::from(h.sessions.min(99)) {
        let sspan = file.sub(
            u64::from(h.sessions_offset).saturating_add(s.saturating_mul(MdsSession::SIZE)),
            MdsSession::SIZE,
        );
        let sess: MdsSession = read_record(&cx, sspan, LE).await?;
        let tspan = file.sub_exact(
            sess.tracks_offset.into(),
            u64::from(sess.blocks).saturating_mul(MdsTrack::SIZE),
        )?;
        for t in 0..u64::from(sess.blocks) {
            let one = tspan.sub(t.saturating_mul(MdsTrack::SIZE), MdsTrack::SIZE);
            let tr: MdsTrack = read_record(&cx, one, LE).await?;
            if tr.point <= 0x99 {
                tracks = tracks.saturating_add(1);
                if image.is_none() && tr.footer_offset != 0 {
                    let raw = cx.read_avail(file.sub(tr.footer_offset.into(), 8)).await?;
                    let name_at = u32_le(&raw, 0).unwrap_or(0);
                    let wide = u32_le(&raw, 4).unwrap_or(0) != 0;
                    let bytes = cx.read_avail(file.sub(name_at.into(), 512)).await?;
                    image = Some(if wide {
                        crate::text::utf16z(&bytes, LE).0
                    } else {
                        crate::text::until_nul(&bytes)
                    });
                }
            }
        }
        cx.emit(
            MdsSession::node(format!("Session {}", sess.number), sspan, LE)
                .summary(format!(
                    "sectors {}..{}, tracks {}-{}",
                    sess.start, sess.end, sess.first_track, sess.last_track
                ))
                .target(tspan),
        );
        cx.emit(
            Node::new(format!("Session {} track blocks", sess.number))
                .span(tspan)
                .summary(plural(sess.blocks, "block"))
                .lazy(mds_tracks, tspan),
        );
    }
    let medium = lookup(MDS_MEDIUM, h.medium.into()).unwrap_or("unknown medium");
    cx.annotate(format!(
        "Alcohol MDS v{}.{}, {medium}, {} session(s), {tracks} track(s){}",
        h.major,
        h.minor,
        h.sessions,
        image.map_or_else(String::new, |i| format!(", image {i:?}"))
    ));
    Ok(())
}

async fn mds_tracks(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / MdsTrack::SIZE;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let one = span.sub(i.saturating_mul(MdsTrack::SIZE), MdsTrack::SIZE);
        let t: MdsTrack = read_record(&cx, one, LE).await?;
        let name = if t.point <= 0x99 {
            format!("Track {}", t.point)
        } else {
            format!("Lead-in entry {:#04x}", t.point)
        };
        let summary = if t.point <= 0x99 {
            format!(
                "{}, {}-byte sectors from LBA {} at {:#x}",
                lookup(MDS_TRACK_MODES, t.mode.into()).unwrap_or("unknown mode"),
                t.sector_size,
                t.start_sector,
                t.start_offset
            )
        } else {
            format!("MSF {:02}:{:02}:{:02}", t.min, t.sec, t.frame)
        };
        cx.push(MdsTrack::node(name, one, LE).summary(summary))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DiscJuggler CDI (descriptor at the end)

fn cdi_probe(h: &Head<'_>) -> bool {
    let n = h.tail.len();
    let version = u32_le(h.tail, n.saturating_sub(8));
    let offset = u32_le(h.tail, n.saturating_sub(4));
    matches!(version, Some(0x8000_0004..=0x8000_0006))
        && offset.is_some_and(|o| o != 0 && u64::from(o) < h.len)
}

declare_format!(pub CDI = "cdi", "DiscJuggler disc image", ["cdi"],
    "application/x-cdi", Probe::Custom(cdi_probe), cdi);

const CDI_VERSIONS: EnumTable = &[
    (0x8000_0004, "2.0"),
    (0x8000_0005, "3.0"),
    (0x8000_0006, "3.5"),
];

async fn cdi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let tail_at = file.len.saturating_sub(8);
    let tail = cx.block(file.sub(tail_at, 8)).await?;
    let mut f = Fields::emitting(&cx, &tail, LE);
    let version = f.u32("Version").enumeration(CDI_VERSIONS).emit()?;
    let offset = u64::from(
        f.u32("Descriptor offset")
            .hex()
            .desc("From the end of the file in version 3.5, from the start otherwise")
            .emit()?,
    );
    let start = if version == 0x8000_0006 {
        file.len.saturating_sub(offset)
    } else {
        offset
    };
    let descriptor = file.sub(start, tail_at.saturating_sub(start));
    let raw = cx.read_avail(descriptor.sub(0, 4)).await?;
    let sessions = u16_le(&raw, 0).unwrap_or(0);
    let tracks = u16_le(&raw, 2).unwrap_or(0);
    cx.emit(
        Node::new("Image data")
            .span(file.sub(0, start))
            .summary(size(start)),
    );
    cx.emit(
        Node::new("Descriptor")
            .span(descriptor)
            .summary(format!(
                "{sessions} session(s), first session has {tracks} track(s)"
            ))
            .lazy(cdi_descriptor, descriptor),
    );
    cx.annotate(format!(
        "DiscJuggler image v{}, {sessions} session(s), {} of data",
        lookup(CDI_VERSIONS, version.into()).unwrap_or("?"),
        size(start)
    ));
    Ok(())
}

async fn cdi_descriptor(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Sessions").emit()?;
    f.u16("Tracks in first session").emit()?;
    cx.emit(
        Node::new("Track descriptors")
            .span(span.tail(4))
            .diag(Diagnostic::unsupported("variable-length CDI track records")),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// CloneCD control file (INI), Dreamcast GDI

fn ccd_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"[CloneCD]")
}

declare_format!(pub CCD = "ccd", "CloneCD control file", ["ccd"],
    "text/x-ccd", Probe::Custom(ccd_probe), ccd);

async fn ccd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read(file.sub(0, file.len.min(1 << 20))).await?;
    let mut sections: Vec<(String, Span, IniEntries)> = Vec::new();
    for (line, span) in lines(&data, file) {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            sections.push((name.to_owned(), span, Vec::new()));
        } else if let Some((k, v)) = trimmed.split_once('=')
            && let Some(last) = sections.last_mut()
        {
            last.2
                .push((k.trim().to_owned(), v.trim().to_owned(), span));
            last.1 = Span {
                len: span.end().saturating_sub(last.1.offset),
                ..last.1
            };
        }
    }
    let get = |section: &str, key: &str| {
        sections
            .iter()
            .find(|s| s.0.eq_ignore_ascii_case(section))
            .and_then(|s| s.2.iter().find(|e| e.0.eq_ignore_ascii_case(key)))
            .map(|e| e.1.clone())
    };
    let version = get("CloneCD", "Version").unwrap_or_default();
    let sessions = get("Disc", "Sessions").unwrap_or_default();
    let entries = get("Disc", "TocEntries").unwrap_or_default();
    let tracks = sections
        .iter()
        .filter(|s| s.0.to_ascii_uppercase().starts_with("TRACK"))
        .count();
    let scrambled = get("Disc", "DataTracksScrambled").is_some_and(|v| v != "0");
    for (name, span, entries) in sections {
        let summary = match name.to_ascii_uppercase().as_str() {
            n if n.starts_with("ENTRY") => {
                let e = |k: &str| {
                    entries
                        .iter()
                        .find(|x| x.0.eq_ignore_ascii_case(k))
                        .map_or("?", |x| x.1.as_str())
                };
                format!(
                    "session {}, point {}, PLBA {}",
                    e("Session"),
                    e("Point"),
                    e("PLBA")
                )
            }
            n if n.starts_with("TRACK") => entries
                .iter()
                .map(|x| format!("{}={}", x.0, x.1))
                .collect::<Vec<_>>()
                .join(", "),
            _ => plural(entries.len(), "key"),
        };
        cx.push(
            Node::new(format!("[{name}]"))
                .span(span)
                .summary(summary)
                .lazy(ini_keys, entries),
        )
        .await;
    }
    cx.annotate(format!(
        "CloneCD v{version}, {sessions} session(s), {entries} TOC entries, {tracks} track(s){}",
        if scrambled {
            ", scrambled data tracks"
        } else {
            ""
        }
    ));
    Ok(())
}

/// `(key, value, line)` triples of one INI section.
type IniEntries = Vec<(String, String, Span)>;

async fn ini_keys(cx: Cx, entries: IniEntries) -> Result<()> {
    for (k, v, span) in entries {
        let value = v
            .parse::<i64>()
            .map_or_else(|_| text(v.clone()), |n| Value::Int { value: n, bits: 64 });
        let value = if let Some(h) = v
            .strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok())
        {
            hex(h, 32)
        } else {
            value
        };
        cx.push(Node::new(k).span(span).value(value)).await;
    }
    Ok(())
}

fn gdi_probe(h: &Head<'_>) -> bool {
    let first = h.data.get(..h.data.len().min(2048)).unwrap_or_default();
    if !is_ascii_text(first) || first.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(first);
    let mut it = text.lines();
    let Some(count) = it.next().and_then(|l| l.trim().parse::<u32>().ok()) else {
        return false;
    };
    let Some(track) = it.next() else { return false };
    let parts: Vec<&str> = track.split_whitespace().collect();
    (1..=99).contains(&count)
        && parts.len() >= 6
        && parts.first() == Some(&"1")
        && parts.get(1) == Some(&"0")
        && matches!(parts.get(3).copied(), Some("2352" | "2048" | "2336"))
}

declare_format!(pub GDI = "gdi", "Dreamcast GD-ROM track list (GDI)", ["gdi"],
    "text/x-gdi", Probe::Custom(gdi_probe), gdi);

async fn gdi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read(file.sub(0, file.len.min(65536))).await?;
    let mut it = lines(&data, file).into_iter();
    let (count, span) = it.next().unwrap_or_else(|| (String::new(), file.sub(0, 0)));
    cx.emit(
        Node::new("Track count")
            .span(span)
            .value(uint(count.trim().parse::<u32>().unwrap_or(0), 32)),
    );
    let mut high = false;
    for (line, span) in it {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let [number, lba, kind, sector, name, ..] = parts.as_slice() else {
            continue;
        };
        let lba_n: u64 = lba.parse().unwrap_or(0);
        if lba_n >= 45000 {
            high = true;
        }
        let kind = if *kind == "4" { "data" } else { "audio" };
        cx.push(
            Node::new(format!("Track {number}"))
                .span(span)
                .value(text(name.trim_matches('"').to_owned()))
                .summary(format!(
                    "{kind}, LBA {lba_n}{}, {sector}-byte sectors",
                    if lba_n >= 45000 {
                        " (high-density area)"
                    } else {
                        ""
                    }
                )),
        )
        .await;
    }
    cx.annotate(format!(
        "GD-ROM track list, {}{}",
        plural(count.trim(), "track"),
        if high { ", with high-density area" } else { "" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// ECM (error code modeler)

declare_format!(pub ECM = "ecm", "Error Code Modeler image (ECM)", ["ecm"],
    "application/x-ecm", Probe::Magic(&[(0, b"ECM\0")]), ecm);

const ECM_TYPES: [(&str, u64, u64); 4] = [
    ("raw bytes", 1, 1),
    ("Mode 1 sectors", 0x803, 2352),
    ("Mode 2 form 1 sectors", 0x804, 2336),
    ("Mode 2 form 2 sectors", 0x918, 2336),
];

async fn ecm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)).value(text("ECM")));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(4);
    let (mut runs, mut decoded) = (0u64, 0u64);
    let mut sectors = [0u64; 4];
    let mut ended = false;
    while !cur.at_end() {
        let start = cur.pos();
        let mut byte = cur.u8().await?;
        let kind = usize::from(byte & 3);
        let mut count = u64::from(byte >> 2 & 0x1f);
        let mut bits = 5u32;
        while byte & 0x80 != 0 && bits < 64 {
            byte = cur.u8().await?;
            count |= u64::from(byte & 0x7f).checked_shl(bits).unwrap_or(0);
            bits = bits.saturating_add(7);
        }
        if count == 0xffff_ffff {
            cx.push(Node::new("End marker").span(cur.since(start)))
                .await;
            ended = true;
            break;
        }
        let count = count.saturating_add(1);
        let (name, stored, out) = ECM_TYPES.get(kind).copied().unwrap_or(("?", 1, 1));
        let body = cur.span(count.saturating_mul(stored));
        cur.skip(count.saturating_mul(stored));
        runs = runs.saturating_add(1);
        decoded = decoded.saturating_add(count.saturating_mul(out));
        if kind > 0
            && let Some(s) = sectors.get_mut(kind)
        {
            *s = s.saturating_add(count);
        }
        cx.push(
            Node::new(format!("Run {runs}"))
                .span(cur.since(start))
                .value(uint(count, 64))
                .summary(format!(
                    "{count} {name} → {} decoded",
                    size(count.saturating_mul(out))
                ))
                .target(body),
        )
        .await;
    }
    if ended && cur.remaining() >= 4 {
        let at = cur.pos();
        let edc = cur.u32().await?;
        cx.emit(
            Node::new("EDC of decoded image")
                .span(cur.since(at))
                .value(hex(edc, 32)),
        );
    } else if !ended {
        cx.diag(Diagnostic::warning("no end marker"));
    }
    let [_, m1, f1, f2] = sectors;
    cx.annotate(format!(
        "ECM image, {runs_run} ({m1} Mode 1, {f1} Mode 2/1, {f2} Mode 2/2 sectors), decodes to {}",
        size(decoded),
        runs_run = plural(runs, "run")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// CSO / ZSO (PSP and PS2 compressed ISOs), DAX

fn cso_probe(h: &Head<'_>) -> bool {
    (h.at(0, b"CISO") || h.at(0, b"ZISO"))
        && matches!(u32_le(h.data, 4), Some(0 | 0x18))
        && u32_le(h.data, 16).is_some_and(|b| b.is_power_of_two() && b >= 512)
}

declare_format!(pub CSO = "cso", "Compressed ISO (CSO/ZSO)", ["cso", "ciso", "zso"],
    "application/x-cso", Probe::Custom(cso_probe), cso);

record! {
    pub struct CsoHeader {
        magic: ascii[4] "Magic",
        header_size: u32 "Header size",
        total: u64 "Uncompressed size",
        block_size: u32 "Block size",
        version: u8 "Version",
        align: u8 "Index alignment (shift)",
        _reserved: bytes[2] "Reserved",
    }
}

async fn cso(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, CsoHeader::SIZE);
    let h: CsoHeader = read_record(&cx, span, LE).await?;
    cx.emit(CsoHeader::node("Header", span, LE));
    let zso = h.magic == "ZISO";
    let blocks = h.total.div_ceil(u64::from(h.block_size.max(1)));
    let index = file.sub_exact(CsoHeader::SIZE, blocks.saturating_add(1).saturating_mul(4))?;
    cx.emit(
        Node::new("Blocks")
            .span(index)
            .summary(plural(blocks, "block"))
            .lazy(
                cso_blocks,
                (
                    input,
                    index,
                    u64::from(h.block_size),
                    u32::from(h.align),
                    zso,
                    h.total,
                ),
            ),
    );
    cx.annotate(format!(
        "{} v{}, {} image in {blocks_block} of {}",
        if zso { "ZSO (LZ4)" } else { "CSO (deflate)" },
        h.version,
        size(h.total),
        size(h.block_size.into()),
        blocks_block = plural(blocks, "block")
    ));
    Ok(())
}

async fn cso_blocks(
    cx: Cx,
    (input, index, block_size, align, zso, total): (Input, Span, u64, u32, bool, u64),
) -> Result<()> {
    let file = input.span;
    let count = (index.len / 4).saturating_sub(1);
    cx.set_count(Count::Exact(count));
    let mut i = 0u64;
    while i < count {
        let raw = cx.read(index.sub(i.saturating_mul(4), 8)).await?;
        let a = u32_le(&raw, 0).unwrap_or(0);
        let b = u32_le(&raw, 4).unwrap_or(0);
        let start = u64::from(a & 0x7fff_ffff).checked_shl(align).unwrap_or(0);
        let end = u64::from(b & 0x7fff_ffff).checked_shl(align).unwrap_or(0);
        let span = file.sub(start, end.saturating_sub(start));
        let plain = a & 0x8000_0000 != 0;
        let name = format!("Block {i}");
        // The last block holds what remains of the image.
        let expected = block_size.min(total.saturating_sub(i.saturating_mul(block_size)));
        let node = if plain {
            Node::new(name).span(span).summary("stored")
        } else if zso {
            // A raw LZ4 block (with `align`, padding after it is an error).
            content(name, input, span, Codec::Lz4Block, Some(expected))
                .summary(format!("LZ4, {} bytes", span.len))
        } else {
            content(name, input, span, Codec::Deflate, Some(expected))
                .summary(format!("deflate, {} bytes", span.len))
        };
        cx.push(node.value(hex(start, 64))).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

declare_format!(pub DAX = "dax", "Compressed ISO (DAX)", ["dax"],
    "application/x-dax", Probe::Magic(&[(0, b"DAX\0")]), dax);

record! {
    pub struct DaxHeader {
        magic: ascii[4] "Magic",
        total: u32 "Uncompressed size",
        version: u32 "Version",
        nc_areas: u32 "Non-compressed areas",
        _reserved: bytes[16] "Reserved",
    }
}

const DAX_FRAME: u64 = 0x2000;

async fn dax(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, DaxHeader::SIZE);
    let h: DaxHeader = read_record(&cx, span, LE).await?;
    cx.emit(DaxHeader::node("Header", span, LE));
    let frames = u64::from(h.total).div_ceil(DAX_FRAME);
    let offsets = file.sub_exact(DaxHeader::SIZE, frames.saturating_mul(4))?;
    let lengths = if h.version >= 1 {
        Some(file.sub_exact(
            offsets.end().saturating_sub(file.offset),
            frames.saturating_mul(2),
        )?)
    } else {
        None
    };
    cx.emit(
        Node::new("Frame offsets")
            .span(offsets)
            .summary(plural(frames, "entry")),
    );
    if let Some(l) = lengths {
        cx.emit(
            Node::new("Frame lengths")
                .span(l)
                .summary(plural(frames, "entry")),
        );
    }
    cx.emit(
        Node::new("Frames")
            .summary(format!(
                "{frames_frame} of 8 KiB",
                frames_frame = plural(frames, "frame")
            ))
            .lazy(dax_frames, (input, offsets, lengths)),
    );
    cx.annotate(format!(
        "DAX v{}, {} image in {frames} zlib frames, {} non-compressed areas",
        h.version,
        size(h.total.into()),
        h.nc_areas
    ));
    Ok(())
}

async fn dax_frames(cx: Cx, (input, offsets, lengths): (Input, Span, Option<Span>)) -> Result<()> {
    let file = input.span;
    let count = offsets.len / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let raw = cx.read(offsets.sub(i.saturating_mul(4), 8)).await?;
        let start = u64::from(u32_le(&raw, 0).unwrap_or(0));
        let len = match lengths {
            Some(l) => {
                u64::from(u16_le(&cx.read(l.sub(i.saturating_mul(2), 2)).await?, 0).unwrap_or(0))
            }
            None => u64::from(u32_le(&raw, 4).unwrap_or(0)).saturating_sub(start),
        };
        let span = file.sub(start, len);
        cx.push(
            content(
                format!("Frame {i}"),
                input,
                span,
                Codec::Zlib,
                Some(DAX_FRAME),
            )
            .value(hex(start, 32))
            .summary(format!("{len} bytes")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ISZ (UltraISO), DAA (PowerISO)

declare_format!(pub ISZ = "isz", "UltraISO compressed image (ISZ)", ["isz"],
    "application/x-isz", Probe::Magic(&[(0, b"IsZ!")]), isz);

const ISZ_ENCRYPTION: EnumTable = &[
    (0, "none"),
    (1, "password"),
    (2, "AES-128"),
    (3, "AES-192"),
    (4, "AES-256"),
];

record! {
    pub struct IszHeader {
        signature: ascii[4] "Signature",
        header_size: u8 "Header size",
        version: u8 "Version",
        serial: u32 "Volume serial number" .hex(),
        sector_size: u16 "Sector size",
        total_sectors: u32 "Total sectors",
        encryption: u8 "Encryption" .enumeration(ISZ_ENCRYPTION),
        segment_size: u64 "Segment size",
        blocks: u32 "Number of chunks",
        block_size: u32 "Chunk size",
        pointer_len: u8 "Chunk pointer length",
        segment: u8 "Segment number",
        pointer_offset: u32 "Chunk pointer table offset" .hex(),
        segment_offset: u32 "Segment table offset" .hex(),
        data_offset: u32 "Data offset" .hex(),
        _reserved: u8 "Reserved",
        checksum1: u32 "Checksum 1" .hex(),
        size1: u32 "Size 1",
        _unknown: u32 "Unknown",
        checksum2: u32 "Checksum 2" .hex(),
    }
}

async fn isz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, IszHeader::SIZE);
    let h: IszHeader = read_record(&cx, span, LE).await?;
    cx.emit(IszHeader::node("Header", span, LE));
    if h.pointer_offset != 0 {
        let len = u64::from(h.blocks).saturating_mul(h.pointer_len.into());
        cx.emit(
            Node::new("Chunk pointer table")
                .span(file.sub(h.pointer_offset.into(), len))
                .desc("Obfuscated with a fixed XOR key"),
        );
    }
    if h.segment_offset != 0 {
        cx.emit(Node::new("Segment table").span(file.sub(h.segment_offset.into(), 24)));
    }
    cx.emit(Node::new("Compressed data").span(file.tail(h.data_offset.into())));
    let total = u64::from(h.total_sectors).saturating_mul(h.sector_size.into());
    cx.annotate(format!(
        "ISZ v{}, {} image in {} of {}, encryption {}",
        h.version,
        size(total),
        plural(h.blocks, "chunk"),
        size(h.block_size.into()),
        lookup(ISZ_ENCRYPTION, h.encryption.into()).unwrap_or("unknown")
    ));
    Ok(())
}

fn daa_probe(h: &Head<'_>) -> bool {
    (h.at(0, b"DAA\0\0\0\0\0\0\0\0\0\0\0\0\0")
        || h.at(0, b"DAA VOL\0")
        || h.at(0, b"GBI\0\0\0\0\0\0\0\0\0\0\0\0\0"))
        && matches!(u32_le(h.data, 0x14), Some(0x100 | 0x110))
}

declare_format!(pub DAA = "daa", "PowerISO direct-access archive (DAA)", ["daa", "gbi"],
    "application/x-daa", Probe::Custom(daa_probe), daa);

record! {
    pub struct DaaHeader {
        signature: ascii[16] "Signature",
        chunk_table: u32 "Chunk table offset" .hex(),
        version: u32 "Format version" .hex(),
        data_offset: u32 "Data offset" .hex(),
        b1: u32 "Unknown (1)",
        b0: u32 "Unknown (0)",
        chunk_size: u32 "Chunk size",
        iso_size: u64 "ISO size",
        daa_size: u64 "DAA size",
        hdata: bytes[16] "Format data",
        crc: u32 "Header CRC" .hex(),
    }
}

async fn daa(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, DaaHeader::SIZE);
    let h: DaaHeader = read_record(&cx, span, LE).await?;
    cx.emit(DaaHeader::node("Header", span, LE));
    let chunks = h.iso_size.div_ceil(u64::from(h.chunk_size.max(1)));
    let table = file.sub(
        h.chunk_table.into(),
        u64::from(h.data_offset).saturating_sub(h.chunk_table.into()),
    );
    cx.emit(
        Node::new("Chunk table")
            .span(table)
            .summary(plural(chunks, "chunk")),
    );
    cx.emit(Node::new("Compressed data").span(file.tail(h.data_offset.into())));
    let computed = crate::codec::crc32(&cx.read(file.sub(0, 0x48)).await?);
    if computed != h.crc {
        cx.diag(Diagnostic::warning(format!(
            "header CRC mismatch: computed {computed:#010x}"
        )));
    }
    cx.annotate(format!(
        "{} v{}.{}, {} ISO in {chunks_chunk} of {}",
        if h.signature.starts_with("GBI") {
            "gBurner image"
        } else if h.signature.starts_with("DAA VOL") {
            "DAA volume"
        } else {
            "PowerISO DAA"
        },
        h.version >> 8,
        h.version >> 4 & 0xf,
        size(h.iso_size),
        size(h.chunk_size.into()),
        chunks_chunk = plural(chunks, "chunk")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GameCube / Wii wrappers: WBFS, GCZ, WIA/RVZ, TGC, CISO

declare_format!(pub WBFS = "wbfs", "Wii Backup File System image", ["wbfs"],
    "application/x-wbfs", Probe::Magic(&[(0, b"WBFS")]), wbfs);

async fn wbfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    let sectors = f.u32("HD sectors").emit()?;
    let hd_shift = f
        .u8("HD sector size (shift)")
        .with(|&v, n| n.summary(size(1u64.checked_shl(v.into()).unwrap_or(0))))
        .emit()?;
    let wbfs_shift = f
        .u8("WBFS sector size (shift)")
        .with(|&v, n| n.summary(size(1u64.checked_shl(v.into()).unwrap_or(0))))
        .emit()?;
    f.u8("Version").emit()?;
    f.u8("Padding").emit()?;
    let hd = 1u64
        .checked_shl(hd_shift.into())
        .unwrap_or(512)
        .clamp(512, 1 << 16);
    let table = file.sub(12, hd.saturating_sub(12).min(500));
    let used = cx.read_avail(table).await?;
    cx.emit(Node::new("Disc table").span(table).summary(format!(
        "{} used",
        plural(used.iter().filter(|&&b| b != 0).count(), "slot")
    )));
    let mut titles = Vec::new();
    for (slot, &flag) in used.iter().enumerate() {
        if flag == 0 {
            continue;
        }
        let at = hd.saturating_mul(crate::bytes::to_u64(slot).saturating_add(1));
        let disc = file.sub(at, hd);
        let raw = cx.read_avail(disc.sub(0, 0x60)).await?;
        let id = String::from_utf8_lossy(raw.get(..6).unwrap_or_default()).into_owned();
        let title = crate::text::until_nul(raw.get(0x20..).unwrap_or_default());
        titles.push(title.clone());
        cx.push(
            Node::new(format!("Disc {slot}"))
                .span(disc)
                .value(text(id))
                .summary(title)
                .lazy(wbfs_disc, disc),
        )
        .await;
    }
    cx.annotate(format!(
        "WBFS, {} of {}, WBFS sectors of {}, {} disc(s){}",
        plural(sectors, "sector"),
        size(hd),
        size(1u64.checked_shl(wbfs_shift.into()).unwrap_or(0)),
        titles.len(),
        titles
            .first()
            .map_or_else(String::new, |t| format!(": {t:?}"))
    ));
    Ok(())
}

async fn wbfs_disc(cx: Cx, disc: Span) -> Result<()> {
    let head = cx.block(disc.sub(0, 0x100)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Game ID", 6).emit()?;
    f.u8("Disc number").emit()?;
    f.u8("Version").emit()?;
    f.bytes("Reserved", 0x10).emit()?;
    f.u32("Wii magic").hex().emit()?;
    f.u32("GameCube magic").hex().emit()?;
    f.ascii("Title", 64).emit()?;
    cx.emit(Node::new("Wii LBA table").span(disc.tail(0x100)));
    Ok(())
}

fn gcz_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(0xb10b_c001)
}

declare_format!(pub GCZ = "gcz", "Dolphin compressed disc image (GCZ)", ["gcz"],
    "application/x-gcz", Probe::Custom(gcz_probe), gcz);

record! {
    pub struct GczHeader {
        magic: u32 "Magic" .hex(),
        sub_type: u32 "Disc type" .enumeration(&[(0, "GameCube"), (1, "Wii")]),
        compressed: u64 "Compressed data size",
        data: u64 "Uncompressed size",
        block_size: u32 "Block size",
        blocks: u32 "Number of blocks",
    }
}

async fn gcz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, GczHeader::SIZE);
    let h: GczHeader = read_record(&cx, span, LE).await?;
    cx.emit(GczHeader::node("Header", span, LE));
    let pointers = file.sub_exact(GczHeader::SIZE, u64::from(h.blocks).saturating_mul(8))?;
    let hashes = file.sub_exact(
        pointers.end().saturating_sub(file.offset),
        u64::from(h.blocks).saturating_mul(4),
    )?;
    let data_start = hashes.end().saturating_sub(file.offset);
    cx.emit(Node::new("Block hashes (Adler-32)").span(hashes));
    cx.emit(
        Node::new("Blocks")
            .span(pointers)
            .summary(plural(h.blocks, "block"))
            .lazy(
                gcz_blocks,
                (
                    input,
                    pointers,
                    data_start,
                    h.compressed,
                    u64::from(h.block_size),
                ),
            ),
    );
    cx.annotate(format!(
        "GCZ {} image, {} → {}, {} of {}",
        if h.sub_type == 1 { "Wii" } else { "GameCube" },
        size(h.data),
        size(h.compressed),
        plural(h.blocks, "block"),
        size(h.block_size.into())
    ));
    Ok(())
}

async fn gcz_blocks(
    cx: Cx,
    (input, pointers, data_start, compressed, block_size): (Input, Span, u64, u64, u64),
) -> Result<()> {
    let file = input.span;
    let count = pointers.len / 8;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let raw = cx.read_avail(pointers.sub(i.saturating_mul(8), 16)).await?;
        let a = u64_le(&raw, 0).unwrap_or(0);
        let next = if i.saturating_add(1) < count {
            u64_le(&raw, 8).unwrap_or(0) & !(1 << 63)
        } else {
            compressed
        };
        let start = a & !(1 << 63);
        let span = file.sub(data_start.saturating_add(start), next.saturating_sub(start));
        let node = if a >> 63 != 0 {
            Node::new(format!("Block {i}")).span(span).summary("stored")
        } else {
            content(
                format!("Block {i}"),
                input,
                span,
                Codec::Zlib,
                Some(block_size),
            )
            .summary(format!("zlib, {} bytes", span.len))
        };
        cx.push(node.value(hex(start, 64))).await;
    }
    Ok(())
}

declare_format!(pub WIA = "wia", "Wii ISO archive (WIA)", ["wia"],
    "application/x-wia", Probe::Magic(&[(0, b"WIA\x01")]), wia);
declare_format!(pub RVZ = "rvz", "Dolphin RVZ disc image", ["rvz"],
    "application/x-rvz", Probe::Magic(&[(0, b"RVZ\x01")]), wia);

const WIA_COMPRESSION: EnumTable = &[
    (0, "none"),
    (1, "purge"),
    (2, "bzip2"),
    (3, "LZMA"),
    (4, "LZMA2"),
    (5, "Zstandard"),
];

fn wia_version(v: u32) -> String {
    format!("{}.{:02}.{:02}", v >> 24, v >> 16 & 0xff, v >> 8 & 0xff)
}

async fn wia(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x48)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.ascii("Magic", 3).emit()?;
    f.u8("Magic version").emit()?;
    let version = f
        .u32("Version")
        .with(|&v, n| n.summary(wia_version(v)))
        .emit()?;
    f.u32("Compatible version")
        .with(|&v, n| n.summary(wia_version(v)))
        .emit()?;
    let h2_size = f.u32("Header 2 size").emit()?;
    f.bytes("Header 2 SHA-1", 20).emit()?;
    let iso = f.u64("ISO size").emit()?;
    let wia_size = f.u64("File size").emit()?;
    f.bytes("Header 1 SHA-1", 20).emit()?;
    let h2 = file.sub(0x48, h2_size.into());
    let raw = cx.read_avail(h2.sub(0, 16)).await?;
    let disc = u32_be(&raw, 0).unwrap_or(0);
    let comp = u32_be(&raw, 4).unwrap_or(0);
    let chunk = u32_be(&raw, 12).unwrap_or(0);
    cx.emit(
        Node::new("Header 2")
            .span(h2)
            .lazy(wia_header2, (input, h2)),
    );
    let title = crate::text::until_nul(&cx.read_avail(h2.sub(0x10 + 0x20, 64)).await?);
    cx.annotate(format!(
        "{magic} {} {} image {title:?}, {} → {}, {} of {}",
        wia_version(version),
        if disc == 2 { "Wii" } else { "GameCube" },
        size(iso),
        size(wia_size),
        plural(
            lookup(WIA_COMPRESSION, comp.into()).unwrap_or("unknown"),
            "chunk"
        ),
        size(chunk.into())
    ));
    Ok(())
}

async fn wia_header2(cx: Cx, (input, h2): (Input, Span)) -> Result<()> {
    let block = cx.block(h2).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Disc type")
        .enumeration(&[(1, "GameCube"), (2, "Wii")])
        .emit()?;
    f.u32("Compression").enumeration(WIA_COMPRESSION).emit()?;
    f.int::<i32>("Compression level").emit()?;
    f.u32("Chunk size").emit()?;
    let disc = f.peek_span(0x80);
    f.skip(0x80);
    f.node(embedded("Disc header", input.nested(disc)));
    f.u32("Partitions").emit()?;
    f.u32("Partition entry size").emit()?;
    f.u64("Partition entries offset").hex().emit()?;
    f.bytes("Partition entries SHA-1", 20).emit()?;
    f.u32("Raw data entries").emit()?;
    f.u64("Raw data entries offset").hex().emit()?;
    f.u32("Raw data entries size").emit()?;
    f.u32("Group entries").emit()?;
    f.u64("Group entries offset").hex().emit()?;
    f.u32("Group entries size").emit()?;
    let len = f.u8("Compressor data size").emit()?;
    f.bytes("Compressor data", len.min(7).into()).emit()?;
    Ok(())
}

fn tgc_probe(h: &Head<'_>) -> bool {
    u32_be(h.data, 0) == Some(0xae0f_38a2)
}

declare_format!(pub TGC = "tgc", "GameCube embedded disc (TGC)", ["tgc"],
    "application/x-tgc", Probe::Custom(tgc_probe), tgc);

record! {
    pub struct TgcHeader {
        magic: u32 "Magic" .hex(),
        _unknown: u32 "Unknown",
        header_size: u32 "Header size" .hex(),
        _unknown2: u32 "Unknown",
        fst_offset: u32 "FST offset" .hex(),
        fst_size: u32 "FST size",
        fst_max: u32 "FST maximum size",
        dol_offset: u32 "DOL offset" .hex(),
        dol_size: u32 "DOL size",
        file_area: u32 "File area offset" .hex(),
        file_area_size: u32 "File area size",
        banner_offset: u32 "Banner offset" .hex(),
        banner_size: u32 "Banner size",
        file_offset: u32 "File offset bias" .hex(),
    }
}

async fn tgc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, TgcHeader::SIZE);
    let h: TgcHeader = read_record(&cx, span, BE).await?;
    cx.emit(TgcHeader::node("Header", span, BE));
    let title = crate::text::until_nul(
        &cx.read_avail(file.sub(u64::from(h.header_size).saturating_add(0x20), 64))
            .await?,
    );
    cx.emit(Node::new("FST").span(file.sub(h.fst_offset.into(), h.fst_size.into())));
    cx.emit(Node::new("DOL executable").span(file.sub(h.dol_offset.into(), h.dol_size.into())));
    cx.emit(Node::new("Banner").span(file.sub(h.banner_offset.into(), h.banner_size.into())));
    cx.emit(embedded(
        "Embedded disc",
        input.nested(file.tail(h.header_size.into())),
    ));
    cx.annotate(format!(
        "TGC {title:?}, DOL {}, FST {}",
        size(h.dol_size.into()),
        size(h.fst_size.into())
    ));
    Ok(())
}

fn wii_ciso_probe(h: &Head<'_>) -> bool {
    h.at(0, b"CISO")
        && u32_le(h.data, 4).is_some_and(|b| b.is_power_of_two() && b >= 0x8000)
        && h.data
            .get(8..h.data.len().min(0x8000))
            .is_some_and(|map| map.iter().all(|&b| b <= 1))
}

declare_format!(pub WII_CISO = "wii-ciso", "Wii/GameCube compact ISO (CISO)", ["ciso"],
    "application/x-wii-ciso", Probe::Custom(wii_ciso_probe), wii_ciso);

async fn wii_ciso(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let block = u64::from(f.u32("Block size").emit()?);
    let map_span = file.sub(8, 0x8000 - 8);
    let map = cx.read_avail(map_span).await?;
    let used = map.iter().filter(|&&b| b == 1).count();
    let last = map
        .iter()
        .rposition(|&b| b == 1)
        .map_or(0, |i| crate::bytes::to_u64(i).saturating_add(1));
    cx.emit(
        Node::new("Block map")
            .span(map_span)
            .summary(format!("{used} of {last} blocks present")),
    );
    cx.emit(embedded(
        "First block",
        input.nested(file.sub(0x8000, block)),
    ));
    cx.annotate(format!(
        "compact ISO, {used_block} of {} stored, image {}",
        size(block),
        size(last.saturating_mul(block)),
        used_block = plural(used, "block")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Sega CD, Saturn, Dreamcast system areas; 3DO Opera file system

fn sega_disc_at(h: &Head<'_>, magic: &[u8]) -> bool {
    h.at(0, magic) || h.at(0x10, magic)
}

fn sega_cd_probe(h: &Head<'_>) -> bool {
    sega_disc_at(h, b"SEGADISCSYSTEM  ") || sega_disc_at(h, b"SEGABOOTDISC    ")
}

fn saturn_probe(h: &Head<'_>) -> bool {
    sega_disc_at(h, b"SEGA SEGASATURN ")
}

fn dreamcast_probe(h: &Head<'_>) -> bool {
    sega_disc_at(h, b"SEGA SEGAKATANA ")
}

declare_format!(pub SEGA_CD = "sega-cd", "Sega CD / Mega-CD disc", ["iso", "bin"],
    "application/x-sega-cd", Probe::Custom(sega_cd_probe), sega_cd);
declare_format!(pub SATURN = "saturn", "Sega Saturn disc", ["iso", "bin"],
    "application/x-saturn-rom", Probe::Custom(saturn_probe), saturn);
declare_format!(pub DREAMCAST = "dreamcast", "Dreamcast disc (IP.BIN)", ["iso", "bin", "gdi"],
    "application/x-dreamcast-rom", Probe::Custom(dreamcast_probe), dreamcast);

/// Bytes per raw CD sector.
const RAW_SECTOR: u64 = 2352;

/// The system area to read the headers from. A 2048-byte-sector image is
/// used as is. A raw (2352-byte-sector) dump frames every 2048 bytes of
/// user data with a sync, a header (and for Mode 2 a subheader) and
/// EDC/ECC, and the system areas run over many sectors (the Saturn IP to
/// 0x1800, the Dreamcast IP to 0x8000, the Sega CD IP and SP), so the user
/// data of every sector is gathered into one piecewise source, which is
/// also offered whole when it carries an ISO 9660 file system.
async fn sega_base(cx: &Cx, input: Input, magic: &[u8]) -> Result<Span> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x20)).await?;
    if head.starts_with(magic) {
        return Ok(file);
    }
    let user: u64 = if head.get(15) == Some(&2) { 24 } else { 16 };
    cx.emit(
        Node::new("Sector sync and header")
            .span(file.sub(0, user))
            .desc("Raw (2352-byte) sector dump"),
    );
    let sectors = file.len.div_ceil(RAW_SECTOR);
    let mut pieces = Vec::new();
    for i in 0..sectors {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let data = file.sub(i.saturating_mul(RAW_SECTOR).saturating_add(user), 2048);
        if data.len > 0 {
            pieces.push(data);
        }
    }
    let area = cx
        .add_pieces_stepped(
            crate::span::Origin {
                parent: file,
                transform: "cd-user-data",
            },
            &pieces,
        )
        .await?;
    // Offered whole only when it holds a file system: the headers below
    // already cover a bare system area.
    let id = cx.read_avail(area.sub(0x8001, 5)).await?;
    if id.as_slice() != b"CD001" {
        return Ok(area);
    }
    cx.emit(embedded("User data", input.nested(area)).summary(format!(
        "{} of {} sectors",
        size(area.len),
        sectors
    )));
    Ok(area)
}

record! {
    pub struct SegaCdVolume {
        disc_type: ascii[16] "Disc type",
        volume: ascii[11] "Volume name",
        _pad: u8 "Padding",
        volume_version: u16 "Volume version" .hex(),
        volume_type: u16 "Volume type" .hex(),
        system: ascii[11] "System name",
        _pad2: u8 "Padding",
        system_version: u16 "System version" .hex(),
        _pad3: u16 "Padding",
        ip_offset: u32 "Initial program offset" .hex(),
        ip_size: u32 "Initial program size" .hex(),
        ip_entry: u32 "Initial program entry" .hex(),
        ip_work: u32 "Initial program work RAM" .hex(),
        sp_offset: u32 "System program offset" .hex(),
        sp_size: u32 "System program size" .hex(),
        sp_entry: u32 "System program entry" .hex(),
        sp_work: u32 "System program work RAM" .hex(),
    }
}

async fn sega_cd(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 0x20)).await?;
    let magic: &[u8] = if head.windows(14).any(|w| w == b"SEGABOOTDISC  ") {
        b"SEGABOOTDISC    "
    } else {
        b"SEGADISCSYSTEM  "
    };
    let area = sega_base(&cx, input, magic).await?;
    let span = area.sub(0, SegaCdVolume::SIZE);
    let v: SegaCdVolume = read_record(&cx, span, BE).await?;
    cx.emit(SegaCdVolume::node("Volume header", span, BE));
    let gspan = area.sub(0x100, super::consoles::GenesisHeader::SIZE);
    let g: super::consoles::GenesisHeader = read_record(&cx, gspan, BE).await?;
    cx.emit(super::consoles::GenesisHeader::node(
        "System header",
        gspan,
        BE,
    ));
    cx.emit(Node::new("Initial program (IP)").span(area.sub(v.ip_offset.into(), v.ip_size.into())));
    cx.emit(Node::new("System program (SP)").span(area.sub(v.sp_offset.into(), v.sp_size.into())));
    let title = if clean(&g.overseas).is_empty() {
        clean(&g.domestic)
    } else {
        clean(&g.overseas)
    };
    let title: String = title.split_whitespace().collect::<Vec<_>>().join(" ");
    cx.annotate(format!(
        "Sega CD {title:?}, {}, serial {}, region {}",
        clean(&g.system),
        clean(&g.serial),
        clean(&g.region)
    ));
    Ok(())
}

const SATURN_AREAS: [(char, &str); 8] = [
    ('J', "Japan"),
    ('T', "Asia NTSC"),
    ('U', "North America"),
    ('B', "Brazil"),
    ('K', "Korea"),
    ('A', "Asia PAL"),
    ('E', "Europe"),
    ('L', "Latin America"),
];

fn areas(codes: &str) -> String {
    let names: Vec<&str> = codes
        .chars()
        .filter_map(|c| SATURN_AREAS.iter().find(|a| a.0 == c).map(|a| a.1))
        .collect();
    names.join(", ")
}

record! {
    pub struct SaturnHeader {
        hardware: ascii[16] "Hardware ID",
        maker: ascii[16] "Maker ID",
        product: ascii[10] "Product number",
        version: ascii[6] "Version",
        date: ascii[8] "Release date (YYYYMMDD)",
        device: ascii[8] "Device information",
        area: ascii[10] "Compatible areas" .with(|v, n| n.summary(areas(v))),
        _spaces: ascii[6] "Reserved",
        peripherals: ascii[16] "Compatible peripherals",
        title: ascii[112] "Game title",
        _reserved: bytes[16] "Reserved",
        ip_size: u32 "IP size" .hex(),
        _reserved2: u32 "Reserved",
        master_stack: u32 "Master SH-2 stack" .hex(),
        slave_stack: u32 "Slave SH-2 stack" .hex(),
        first_read: u32 "1st read address" .hex(),
        first_read_size: u32 "1st read size" .hex(),
        _reserved3: bytes[8] "Reserved",
    }
}

async fn saturn(cx: Cx, input: Input) -> Result<()> {
    let area = sega_base(&cx, input, b"SEGA SEGASATURN ").await?;
    let span = area.sub(0, SaturnHeader::SIZE);
    let h: SaturnHeader = read_record(&cx, span, BE).await?;
    cx.emit(SaturnHeader::node("System ID", span, BE));
    cx.emit(
        Node::new("Security code and area code")
            .span(area.sub(0x100, h.ip_size.saturating_sub(0x100).into())),
    );
    let title: String = clean(&h.title)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    cx.annotate(format!(
        "Saturn {title:?} ({} {}), {}, {}",
        clean(&h.product),
        clean(&h.version),
        clean(&h.date),
        areas(&h.area)
    ));
    Ok(())
}

record! {
    pub struct DreamcastHeader {
        hardware: ascii[16] "Hardware ID",
        maker: ascii[16] "Maker ID",
        device: ascii[16] "Device information",
        area: ascii[8] "Area symbols" .with(|v, n| n.summary(areas(v))),
        peripherals: ascii[8] "Peripherals (hex)",
        product: ascii[10] "Product number",
        version: ascii[6] "Version",
        date: ascii[16] "Release date",
        boot: ascii[16] "Boot file",
        publisher: ascii[16] "Software maker",
        title: ascii[128] "Game title",
    }
}

async fn dreamcast(cx: Cx, input: Input) -> Result<()> {
    let area = sega_base(&cx, input, b"SEGA SEGAKATANA ").await?;
    let span = area.sub(0, DreamcastHeader::SIZE);
    let h: DreamcastHeader = read_record(&cx, span, LE).await?;
    cx.emit(DreamcastHeader::node("Meta information", span, LE));
    cx.emit(Node::new("Table of contents").span(area.sub(0x100, 0x200)));
    cx.emit(Node::new("Licence screen code").span(area.sub(0x300, 0x3400)));
    cx.emit(Node::new("Area protection symbols").span(area.sub(0x3700, 0x100)));
    cx.emit(Node::new("Bootstrap").span(area.sub(0x3800, 0x4800)));
    cx.annotate(format!(
        "Dreamcast {:?} ({} {}), by {}, boots {}, {}",
        clean(&h.title),
        clean(&h.product),
        clean(&h.version),
        clean(&h.publisher),
        clean(&h.boot),
        areas(&h.area)
    ));
    Ok(())
}

declare_format!(pub OPERA = "3do", "3DO Opera file system", ["iso", "3do"],
    "application/x-3do", Probe::Magic(&[(0, b"\x01\x5a\x5a\x5a\x5a\x5a\x01")]), opera);

const OPERA_FLAGS: FlagTable = &[field(0x01, 0x01, "DATADISC"), flag(0x02, "BLESSED")];

record! {
    pub struct OperaLabel {
        record_type: u8 "Record type",
        sync: bytes[5] "Sync bytes",
        version: u8 "Structure version",
        flags: u8 "Volume flags" .flags(OPERA_FLAGS),
        comment: ascii[32] "Volume comment",
        label: ascii[32] "Volume label",
        id: u32 "Volume identifier" .hex(),
        block_size: u32 "Block size",
        block_count: u32 "Block count",
        root_id: u32 "Root directory identifier" .hex(),
        root_blocks: u32 "Root directory blocks",
        root_block_size: u32 "Root directory block size",
        last_copy: u32 "Last root directory copy",
        copies: bytes[32] "Root directory copy locations",
    }
}

async fn opera(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, OperaLabel::SIZE);
    let h: OperaLabel = read_record(&cx, span, BE).await?;
    cx.emit(OperaLabel::node("Volume label", span, BE));
    let root = cx.read_avail(span.sub(0x64, 4)).await?;
    let root_block = u64::from(u32_be(&root, 0).unwrap_or(0));
    let bs = u64::from(h.block_size);
    let dir = file.sub(
        root_block.saturating_mul(bs),
        u64::from(h.root_blocks).saturating_mul(u64::from(h.root_block_size)),
    );
    cx.emit(
        Node::new("Root directory")
            .span(dir)
            .summary(format!("{} block(s)", h.root_blocks)),
    );
    cx.annotate(format!(
        "3DO disc {:?}, {} of {} bytes ({})",
        clean(&h.label),
        plural(h.block_count, "block"),
        h.block_size,
        size(u64::from(h.block_count).saturating_mul(bs))
    ));
    Ok(())
}
