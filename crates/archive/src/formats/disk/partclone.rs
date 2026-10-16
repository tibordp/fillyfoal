//! Partclone images (`partclone.<fs> -c`, the image format of Clonezilla).
//!
//! An image is a header, a bitmap saying which blocks of the volume are in
//! use, and the blocks in use in order, with check values between them:
//!
//! - **Format 0002** (partclone 0.2.89 and later): a 36-byte head (the
//!   magic `partclone-image`, the partclone version that wrote it, the
//!   image version `0002`, and `0xC0DE` in the writer's byte order), a
//!   52-byte description of the file system (its type, the device size,
//!   the block count, the blocks in use, the block size), the options
//!   (their own size first: checksum mode and size, blocks per checksum,
//!   whether the CRC restarts at each, the bitmap mode) and a CRC-32 of all
//!   that. The bitmap has a bit per block and its own CRC-32.
//! - **Format 0001** (partclone 0.2.x): a 4160-byte header (magic, file
//!   system type, version `0001`, block size, device size, block count,
//!   blocks in use, then 4096 reserved bytes), a bitmap of a byte per
//!   block, and the magic `BiTmAgIc`.
//!
//! The volume is the block area decoded on demand (`Codec::Partclone`): the
//! bitmap says where each block is stored, so a far read starts from the
//! nearest of a set of resume points computed from the bitmap, and decodes
//! at most one spacing's worth of blocks; the volume is dissected as nested
//! content (the file system that was saved). The block listing walks the
//! bitmap, coalescing runs, and points into the image and the volume.
//!
//! Images piped through gzip or zstd (`partclone.<fs> -c -o - | gzip`) are
//! that format's files whose content is identified as this. Neither records
//! the decoded size, so that content's length is unknown until it has been
//! decoded to its end; this is a streaming format (`formats::STREAMING`),
//! which needs nothing from the length: the header and bitmap are at the
//! start, and the volume decodes on demand through both stages.
//!
//! Checked against images written by partclone 0.3.36 (format 0002: FAT16
//! and ext2 volumes, CRC32 checksums with and without reseeding, none, and
//! through gzip and zstd) and 0.2.73 (format 0001), fixtures in
//! `tests/fixtures/external/`; the layout was written from memory of
//! partclone's headers and confirmed field by field on those images (no
//! partclone code was read or copied). Format 0001 images
//! have no byte-order mark and are read as little-endian, the order of every
//! machine known to have written them.

use std::sync::Arc;

use crate::codec::crc::crc32_update;
use crate::codec::partclone::{Check, MAX_BLOCK, Params, Partclone};
use crate::cx::{Cx, Seed};
use crate::dsl::Record;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::size;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Codec, Format, Input, Probe, dissect_or_data};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

pub static FORMAT: Format = Format {
    name: "partclone",
    title: "Partclone image",
    extensions: &["partclone"],
    mime: "application/x-partclone-image",
    probe: Probe::Magic(&[(0, b"partclone-image")]),
    dissect: crate::expander!(dissect: Input),
};

const CHECKSUM_MODES: EnumTable = &[(0, "NONE"), (0x20, "CRC32"), (0xff, "CRC32_0001")];
const BITMAP_MODES: EnumTable = &[(0, "NONE"), (1, "BIT"), (8, "BYTE")];
/// The option fields this dissector knows (format 0002).
const OPTIONS_SIZE: u64 = 18;
/// Bytes of options shown, at most (a crafted size can be gigabytes).
const MAX_OPTIONS: u64 = 4096;
/// Blocks a run node of the listing covers at most.
const MAX_RUN: u64 = 1 << 16;
/// Bitmap bytes read and walked per step.
const CHUNK: u64 = 1 << 16;
/// Resume points of the volume: at least this far apart, and at most
/// `MAX_SEEDS` of them.
const SEED_SPACING: u64 = 4 << 20;
const MAX_SEEDS: u64 = 16_384;
const V1_MAGIC: &[u8; 8] = b"BiTmAgIc";

record! {
    /// Format 0002: the image head.
    pub struct HeadV2 {
        magic: ascii[16] "Magic",
        tool: ascii[14] "Partclone version" .desc("The partclone version that wrote the image"),
        version: ascii[4] "Image version",
        endian: u16 "Byte order mark" .hex() .desc("0xC0DE in the byte order of the machine that wrote the image"),
    }
}

record! {
    /// Format 0002: the file system.
    pub struct FsInfo {
        fs: ascii[16] "File system",
        device_size: u64 "Device size" .with(|&v, n| n.summary(size(v))),
        blocks: u64 "Blocks",
        used: u64 "Blocks in use",
        used_bitmap: u64 "Blocks in use (bitmap)" .desc("Blocks the bitmap marks, as counted when it was written"),
        block_size: u32 "Block size" .with(|&v, n| n.summary(size(v.into()))),
    }
}

record! {
    /// Format 0002: the options.
    pub struct Options {
        feature_size: u32 "Options size",
        image_version: u16 "Image version" .hex(),
        cpu_bits: u16 "CPU bits" .desc("Word size of the machine that wrote the image"),
        checksum_mode: u16 "Checksum mode" .hex() .enumeration(CHECKSUM_MODES),
        checksum_size: u16 "Checksum size",
        blocks_per_checksum: u32 "Blocks per checksum",
        reseed: u8 "Reseed checksum" .with(|&v, n| n.value(Value::Bool(v != 0))) .desc("Whether the CRC restarts after each check value"),
        bitmap_mode: u8 "Bitmap mode" .enumeration(BITMAP_MODES),
    }
}

record! {
    /// Format 0001: the header.
    pub struct HeaderV1 {
        magic: ascii[15] "Magic",
        fs: ascii[15] "File system",
        version: ascii[4] "Image version",
        _padding: bytes[2] "Padding",
        block_size: u32 "Block size" .with(|&v, n| n.summary(size(v.into()))),
        device_size: u64 "Device size" .with(|&v, n| n.summary(size(v))),
        blocks: u64 "Blocks",
        used: u64 "Blocks in use",
        _reserved: bytes[4096] "Reserved",
    }
}

/// The bitmap's layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Map {
    /// A bit per block, least significant first, then a CRC-32.
    Bits,
    /// A byte per block (non-zero: in use); format 0001 follows it with
    /// `BiTmAgIc`, format 0002 with a CRC-32.
    Bytes { v1: bool },
}

/// What the expanders share.
struct State {
    input: Input,
    /// The bitmap's bytes (fewer than `map_len` if the image is cut).
    bitmap: Span,
    map_len: u64,
    map: Map,
    /// The block area: from after the bitmap to the end of the input.
    stream: Span,
    block_size: u32,
    blocks: u64,
    /// Blocks in use by the header.
    used: u64,
    check: Check,
    /// Check values are big-endian (the writer's byte order).
    big_endian: bool,
}

/// The bitmap, read and walked once.
struct Loaded {
    params: Arc<Params>,
    /// The CRC-32 register over the bitmap's bytes.
    crc: u32,
    /// Resume points: a block and the stored blocks before it.
    seeds: Vec<(u64, u64)>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 36)).await?;
    let version = head.get(30..34).unwrap_or_default();
    if version == b"0001" {
        return dissect_v1(cx, input).await;
    }
    let endian = match head.get(34..36) {
        Some([0xc0, 0xde]) => Endian::Big,
        _ => Endian::Little,
    };
    let h = parse(&cx, file.sub(0, HeadV2::SIZE), endian, &(), HeadV2::layout).await?;
    let mut head_node = HeadV2::node("Image head", file.sub(0, HeadV2::SIZE), endian);
    if h.version != "0002" {
        head_node = head_node.diag(Diagnostic::unsupported(format!(
            "image version {:?} (known: 0001, 0002)",
            h.version
        )));
        cx.emit(head_node);
        return Err(Diagnostic::unsupported(format!(
            "Partclone image version {:?}",
            h.version
        )));
    }
    if h.endian != 0xc0de {
        head_node = head_node.diag(Diagnostic::warning(format!(
            "byte order mark {:#06x} (expected 0xc0de)",
            h.endian
        )));
    }
    cx.emit(head_node);
    let fs_span = file.sub(HeadV2::SIZE, FsInfo::SIZE);
    let fs = parse(&cx, fs_span, endian, &(), FsInfo::layout).await?;
    cx.emit(fs_note(
        FsInfo::node("File system", fs_span, endian).summary(format!(
            "{}, {} blocks of {} bytes, {} in use",
            fs.fs, fs.blocks, fs.block_size, fs.used
        )),
        fs.device_size,
        fs.blocks,
        fs.block_size,
    ));
    let opt_at = HeadV2::SIZE.saturating_add(FsInfo::SIZE);
    let o = parse(
        &cx,
        file.sub(opt_at, Options::SIZE),
        endian,
        &(),
        Options::layout,
    )
    .await?;
    let opt_len = u64::from(o.feature_size);
    let checks = match (o.checksum_mode, o.blocks_per_checksum) {
        (0, _) => "no check values".to_string(),
        (mode, every) => format!(
            "{} every {}{}",
            crate::formats::util::val::name_or(CHECKSUM_MODES, mode.into(), "checksum mode "),
            plural(every, "block"),
            if o.reseed != 0 { ", reseeded" } else { "" }
        ),
    };
    let mut opt_node = Options::node(
        "Options",
        file.sub(opt_at, opt_len.clamp(OPTIONS_SIZE, MAX_OPTIONS)),
        endian,
    )
    .summary(format!(
        "{checks}, bitmap {}",
        crate::formats::util::val::name_or(BITMAP_MODES, o.bitmap_mode.into(), "mode ")
    ));
    if opt_len < OPTIONS_SIZE {
        opt_node = opt_node.diag(Diagnostic::malformed(format!(
            "options size {opt_len} (at least {OPTIONS_SIZE})"
        )));
    }
    cx.emit(opt_node);
    let crc_at = opt_at.saturating_add(opt_len.max(OPTIONS_SIZE));
    let crc_span = file.sub(crc_at, 4);
    let raw = cx
        .read_avail(
            file.sub(
                0,
                crc_at
                    .saturating_add(4)
                    .min(MAX_OPTIONS.saturating_add(opt_at).saturating_add(4)),
            ),
        )
        .await?;
    let stored = raw
        .get(crate::bytes::to_usize(crc_at)..)
        .and_then(|b| b.get(..4))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(|b| match endian {
            Endian::Big => u32::from_be_bytes(b),
            Endian::Little => u32::from_le_bytes(b),
        });
    let Some(stored) = stored else {
        return Err(Diagnostic::truncated(crc_span, 0));
    };
    let covered = raw
        .get(..crate::bytes::to_usize(crc_at))
        .unwrap_or_default();
    let computed = crc32_update(0xffff_ffff, covered);
    let mut crc_node = Node::new("Header checksum")
        .span(crc_span)
        .value(hex(stored, 32))
        .desc("CRC-32 register (no final inversion) over the header before it");
    if computed != stored {
        crc_node = crc_node.diag(Diagnostic::warning(format!(
            "header checksum {stored:#010x}, computed {computed:#010x}"
        )));
    }
    cx.emit(crc_node);
    let header_len = crc_at.saturating_add(4);

    let map = match o.bitmap_mode {
        1 => Some(Map::Bits),
        8 => Some(Map::Bytes { v1: false }),
        _ => None,
    };
    let check = match (o.checksum_mode, o.checksum_size, o.blocks_per_checksum) {
        (0, 0, _) => Ok(Check::None),
        (_, size, 0) if size > 0 => Err(Diagnostic::malformed(format!(
            "{size}-byte check values every 0 blocks"
        ))),
        (0x20, 4, every) => Ok(Check::Crc32 {
            every,
            reseed: o.reseed != 0,
        }),
        (_, size, every) => Ok(Check::Other {
            size: size.into(),
            every,
        }),
    };
    cx.annotate(format!(
        "Partclone image 0002 (partclone {}), {}, {} volume, {} blocks of {} bytes, {} in use",
        h.tool,
        fs.fs,
        size(fs.blocks.saturating_mul(fs.block_size.into())),
        fs.blocks,
        fs.block_size,
        fs.used
    ));
    let Some(map) = map else {
        return Err(Diagnostic::unsupported(format!(
            "bitmap mode {}",
            o.bitmap_mode
        )));
    };
    let check = check?;
    if matches!(check, Check::Other { .. }) {
        cx.diag(Diagnostic::note(format!(
            "checksum mode {:#x} ({}-byte values): not verified",
            o.checksum_mode, o.checksum_size
        )));
    }
    finish(
        &cx,
        input,
        header_len,
        map,
        &fs.fs,
        fs.block_size,
        fs.blocks,
        fs.used,
        check,
        endian,
    )
    .await
}

/// A note on the file system node when the device is not what the
/// blocks cover (the volume is the blocks; partclone.dd, or a file system
/// smaller than its partition).
fn fs_note(node: Node, device: u64, blocks: u64, block_size: u32) -> Node {
    let covered = blocks.saturating_mul(block_size.into());
    if device == covered {
        return node;
    }
    node.diag(Diagnostic::note(format!(
        "the device is {}; its {} blocks cover {}, the volume shown",
        size(device),
        blocks,
        size(covered)
    )))
}

async fn dissect_v1(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, HeaderV1::SIZE);
    let h = parse(&cx, span, Endian::Little, &(), HeaderV1::layout).await?;
    cx.emit(fs_note(
        HeaderV1::node("Header", span, Endian::Little).summary(format!(
            "{}, {} blocks of {} bytes, {} in use",
            h.fs, h.blocks, h.block_size, h.used
        )),
        h.device_size,
        h.blocks,
        h.block_size,
    ));
    cx.annotate(format!(
        "Partclone image 0001, {}, {} volume, {} blocks of {} bytes, {} in use",
        h.fs,
        size(h.blocks.saturating_mul(h.block_size.into())),
        h.blocks,
        h.block_size,
        h.used
    ));
    let map = Map::Bytes { v1: true };
    finish(
        &cx,
        input,
        HeaderV1::SIZE,
        map,
        &h.fs,
        h.block_size,
        h.blocks,
        h.used,
        Check::V1,
        Endian::Little,
    )
    .await
}

/// The bitmap and what follows it, for both formats.
#[allow(clippy::too_many_arguments)]
async fn finish(
    cx: &Cx,
    input: Input,
    header_len: u64,
    map: Map,
    _fs: &str,
    block_size: u32,
    blocks: u64,
    used: u64,
    check: Check,
    endian: Endian,
) -> Result<()> {
    let file = input.span;
    if block_size == 0 || block_size > MAX_BLOCK {
        return Err(
            Diagnostic::unsupported(format!("block size {block_size:#x}"))
                .at(file.sub(0, header_len)),
        );
    }
    let map_len = match map {
        Map::Bits => blocks.div_ceil(8),
        Map::Bytes { .. } => blocks,
    };
    let bitmap = file.sub(header_len, map_len);
    let state = Arc::new(State {
        input,
        bitmap,
        map_len,
        map,
        stream: file.tail(
            header_len
                .saturating_add(map_len)
                .saturating_add(match map {
                    Map::Bytes { v1: true } => 8,
                    _ => 4,
                })
                .min(file.len),
        ),
        block_size,
        blocks,
        used,
        check,
        big_endian: endian == Endian::Big,
    });
    cx.emit(
        Node::new("Bitmap")
            .span(bitmap)
            .summary(match map {
                Map::Bits => format!("{}, a bit per block", plural(blocks, "block")),
                Map::Bytes { .. } => format!("{}, a byte per block", plural(blocks, "block")),
            })
            .lazy(bitmap_node, state.clone()),
    );
    let after = file.sub(
        header_len.saturating_add(map_len),
        match map {
            Map::Bytes { v1: true } => 8,
            _ => 4,
        },
    );
    match map {
        Map::Bytes { v1: true } => {
            let raw = cx.read_avail(after).await?;
            let mut node = Node::new("Bitmap magic")
                .span(after)
                .value(text(String::from_utf8_lossy(&raw)));
            if raw != V1_MAGIC {
                node = node.diag(Diagnostic::malformed("not BiTmAgIc"));
            }
            cx.emit(node);
        }
        _ => {
            let raw = cx.read_avail(after).await?;
            let v = <[u8; 4]>::try_from(raw.as_slice())
                .ok()
                .map(|b| match endian {
                    Endian::Big => u32::from_be_bytes(b),
                    Endian::Little => u32::from_le_bytes(b),
                });
            let mut node = Node::new("Bitmap checksum")
                .span(after)
                .desc("CRC-32 register (no final inversion) over the bitmap; checked when the bitmap is expanded");
            if let Some(v) = v {
                node = node.value(hex(v, 32));
            }
            cx.emit(node);
        }
    }
    // No spans on these two: the block area's end is not known yet when the
    // image is the content of a stream decoded on demand (this is a
    // streaming format), and the tree must not depend on it.
    cx.emit(
        Node::new("Volume")
            .summary(size(blocks.saturating_mul(block_size.into())))
            .desc("The volume restored from the blocks in use, decoded as far as reads reach")
            .lazy(volume, state.clone()),
    );
    cx.emit(
        Node::new("Blocks")
            .summary("runs of blocks in use and free")
            .lazy(listing, state),
    );
    Ok(())
}

/// Reads and walks the bitmap (once per session).
async fn load(cx: &Cx, state: &State) -> Result<Arc<Loaded>> {
    const KIND: &str = "partclone-bitmap";
    if let Some(found) = cx.cached::<Loaded>(state.bitmap, KIND) {
        return Ok(found);
    }
    if state.bitmap.len < state.map_len {
        return Err(Diagnostic::truncated(state.bitmap, state.bitmap.len));
    }
    let bs = u64::from(state.block_size);
    let volume_len = state.blocks.saturating_mul(bs);
    let spacing = SEED_SPACING.max(volume_len / MAX_SEEDS);
    // Seeds are taken at whole bitmap bytes (multiples of 8 blocks).
    let spacing_blocks = (spacing.checked_div(bs).unwrap_or(0) & !7).max(8);
    let mut bits: Vec<u8> = Vec::new();
    let mut crc = 0xffff_ffffu32;
    let mut stored = 0u64;
    let mut seeds = Vec::new();
    let mut block = 0u64;
    let mut pos = 0u64;
    let map = state.map;
    let mut pending = 0u8;
    while pos < state.bitmap.len {
        let n = CHUNK.min(state.bitmap.len.saturating_sub(pos));
        let span = state.bitmap.sub_exact(pos, n)?;
        let raw = cx.read(span).await?;
        crc = crc32_update(crc, &raw);
        match map {
            Map::Bits => {
                for &b in &raw {
                    if block > 0 && block.is_multiple_of(spacing_blocks) {
                        seeds.push((block, stored));
                    }
                    let left = state.blocks.saturating_sub(block);
                    let v = if left < 8 {
                        b & u32::try_from(8u64.saturating_sub(left))
                            .ok()
                            .and_then(|n| 0xffu8.checked_shr(n))
                            .unwrap_or(0)
                    } else {
                        b
                    };
                    stored = stored.saturating_add(u64::from(v.count_ones()));
                    bits.push(v);
                    block = block.saturating_add(8);
                }
            }
            Map::Bytes { .. } => {
                for &b in &raw {
                    let bit = block % 8;
                    if bit == 0 && block > 0 && block.is_multiple_of(spacing_blocks) {
                        seeds.push((block, stored));
                    }
                    if b != 0 {
                        pending |= 1 << bit;
                        stored = stored.saturating_add(1);
                    }
                    block = block.saturating_add(1);
                    if bit == 7 {
                        bits.push(pending);
                        pending = 0;
                    }
                }
            }
        }
        cx.charge(n / 1024).await;
        pos = pos.saturating_add(n);
    }
    if !block.is_multiple_of(8) && matches!(map, Map::Bytes { .. }) {
        bits.push(pending);
    }
    let loaded = Arc::new(Loaded {
        params: Arc::new(Params {
            block_size: state.block_size,
            blocks: state.blocks,
            bitmap: Arc::from(bits),
            stored,
            check: state.check,
            big_endian: state.big_endian,
        }),
        crc,
        seeds,
    });
    cx.cache(state.bitmap, KIND, loaded.clone());
    Ok(loaded)
}

async fn bitmap_node(cx: Cx, state: Arc<State>) -> Result<()> {
    let loaded = load(&cx, &state).await?;
    let stored = loaded.params.stored;
    let mut node = Node::new("Blocks in use").value(uint(stored, 64));
    if stored != state.used {
        node = node.diag(Diagnostic::warning(format!(
            "the bitmap marks {stored} blocks; the header says {} in use",
            state.used
        )));
    }
    cx.emit(node);
    if state.map != (Map::Bytes { v1: true }) {
        let after = state.bitmap.end();
        let span = Span::new(state.bitmap.source, after, 4);
        let raw = cx.read(span).await?;
        let le = <[u8; 4]>::try_from(raw.as_slice())
            .map(u32::from_le_bytes)
            .unwrap_or(0);
        let be = <[u8; 4]>::try_from(raw.as_slice())
            .map(u32::from_be_bytes)
            .unwrap_or(0);
        let mut node = Node::new("Computed checksum")
            .span(span)
            .value(hex(loaded.crc, 32))
            .desc("CRC-32 register over the bitmap");
        if loaded.crc != le && loaded.crc != be {
            node = node.diag(Diagnostic::warning(format!(
                "bitmap checksum {le:#010x}, computed {:#010x}",
                loaded.crc
            )));
        }
        cx.emit(node);
    }
    Ok(())
}

/// The volume, with resume points from the bitmap.
fn register(cx: &Cx, state: &State, loaded: &Loaded) -> Result<Span> {
    let p = &loaded.params;
    let seeds = loaded
        .seeds
        .iter()
        .map(|&(block, stored)| Seed {
            out_pos: block.saturating_mul(p.block_size.into()),
            in_pos: p.check.offset(p.block_size, stored),
            decoder: Box::new(Partclone::seed(p.clone(), block, stored)),
        })
        .collect();
    cx.decode_lazy_seeded(
        state.stream,
        &Codec::Partclone(p.clone()),
        p.volume_len(),
        seeds,
    )
}

async fn volume(cx: Cx, state: Arc<State>) -> Result<()> {
    let loaded = load(&cx, &state).await?;
    let span = register(&cx, &state, &loaded)?;
    dissect_or_data(cx, state.input.nested(span)).await
}

/// Lists the blocks as runs in use and free, with the check values, from
/// resume marks when the host seeks.
async fn listing(cx: Cx, state: Arc<State>) -> Result<()> {
    let loaded = load(&cx, &state).await?;
    let p = loaded.params.clone();
    let volume = register(&cx, &state, &loaded).ok();
    let stream = state.stream;
    let bs = u64::from(p.block_size);
    let (size_cv, every) = p.check.layout();
    let separate = !matches!(p.check, Check::V1 | Check::None);
    // Next block, stored blocks before it, whether a check value is due.
    let (mut block, mut stored, mut due) = cx.resume::<(u64, u64, bool)>().unwrap_or((0, 0, false));
    let offset = |stored: u64| p.check.offset(p.block_size, stored);
    // Where the check value after stored block `stored - 1` is: counted by
    // `offset` after a whole group, after it for the last, partial one.
    let check_at = |stored: u64| {
        if stored.is_multiple_of(every) {
            offset(stored).saturating_sub(size_cv)
        } else {
            offset(stored)
        }
    };
    loop {
        let mark = (block, stored, due);
        if due {
            let span = stream.sub(check_at(stored), size_cv);
            let raw = cx.read_avail(span).await?;
            let mut node = Node::new("Check value").span(span);
            let value = <[u8; 4]>::try_from(raw.as_slice()).ok().map(|b| {
                if p.big_endian {
                    u32::from_be_bytes(b)
                } else {
                    u32::from_le_bytes(b)
                }
            });
            if let Some(v) = value {
                node = node.value(hex(v, 32));
            }
            node = node.summary(format!("after stored block {}", stored.saturating_sub(1)));
            if let (Check::Crc32 { .. }, Some(v)) = (p.check, value) {
                node = node.lazy(verify, (state.clone(), stored, v));
            }
            cx.mark(move || mark);
            cx.push(node).await;
            due = false;
            continue;
        }
        if block >= p.blocks {
            break;
        }
        cx.progress(block, p.blocks);
        let first = block;
        let node = if p.used(block) {
            let start = offset(stored);
            // A run of blocks in use, up to the next check value.
            let room = if separate {
                every.saturating_sub(stored.checked_rem(every).unwrap_or(0))
            } else {
                MAX_RUN
            };
            let limit = room.min(MAX_RUN);
            let mut n = 0u64;
            while n < limit && block < p.blocks && p.used(block) {
                n = n.saturating_add(1);
                block = block.saturating_add(1);
                if n.is_multiple_of(4096) {
                    cx.checkpoint().await;
                }
            }
            stored = stored.saturating_add(n);
            due = separate && (stored.is_multiple_of(every) || stored == p.stored);
            let end = if due {
                check_at(stored)
            } else {
                offset(stored)
            };
            let span = stream.sub(start, end.saturating_sub(start));
            let mut node = Node::new(run_name(first, block))
                .span(span)
                .summary(format!("in use, {}", size(n.saturating_mul(bs))));
            if let Some(v) = volume {
                node = node.target(v.sub(first.saturating_mul(bs), n.saturating_mul(bs)));
            }
            node
        } else {
            let n = free_run(&cx, &p, block).await;
            block = block.saturating_add(n);
            let mut node = Node::new(run_name(first, block))
                .summary(format!("free, {}", size(n.saturating_mul(bs))));
            if let Some(v) = volume {
                node = node.target(v.sub(first.saturating_mul(bs), n.saturating_mul(bs)));
            }
            node
        };
        cx.mark(move || mark);
        cx.push(node).await;
    }
    let end = if size_cv > 0 && stored > 0 && !stored.is_multiple_of(every) {
        offset(stored).saturating_add(size_cv)
    } else {
        offset(stored)
    };
    let known = cx.known(stream).await;
    if known.len < end {
        cx.diag(
            Diagnostic::new(
                DiagKind::Truncated,
                format!(
                    "the image ends {} before the last block in use",
                    plural(end.saturating_sub(known.len), "byte")
                ),
            )
            .at(known.tail(known.len)),
        );
    } else if known.len > end {
        let span = known.tail(end);
        let mark = (block, stored, due);
        cx.mark(move || mark);
        cx.push(
            Node::new("Trailing data")
                .span(span)
                .summary(size(span.len))
                .diag(
                    Diagnostic::warning(format!(
                        "{} after the last block in use",
                        plural(span.len, "byte")
                    ))
                    .at(span),
                ),
        )
        .await;
    }
    Ok(())
}

/// Checks the check value after the first `stored` stored blocks: reads
/// the blocks it covers (since the previous one, or since the start
/// without reseeding), a bounded chunk at a time.
async fn verify(cx: Cx, (state, stored, value): (Arc<State>, u64, u32)) -> Result<()> {
    let Check::Crc32 { every, reseed } = state.check else {
        return Ok(());
    };
    let every = u64::from(every.max(1));
    let bs = u64::from(state.block_size);
    let last_group = stored.saturating_sub(1).checked_div(every).unwrap_or(0);
    let first_group = if reseed { last_group } else { 0 };
    let mut crc = 0xffff_ffffu32;
    for g in first_group..=last_group {
        let first = g.saturating_mul(every);
        let n = every.min(stored.saturating_sub(first));
        let data = state.check.offset(state.block_size, first);
        let len = n.saturating_mul(bs);
        let mut pos = 0u64;
        while pos < len {
            let chunk = CHUNK.min(len.saturating_sub(pos));
            let raw = cx
                .read(state.stream.sub_exact(data.saturating_add(pos), chunk)?)
                .await?;
            crc = crc32_update(crc, &raw);
            cx.charge(chunk / 1024).await;
            pos = pos.saturating_add(chunk);
        }
    }
    let mut node = Node::new("Computed").value(hex(crc, 32)).desc(if reseed {
        "CRC-32 register over the blocks since the previous check value"
    } else {
        "CRC-32 register over every block before it"
    });
    if crc != value {
        node = node.diag(Diagnostic::warning(format!(
            "check value {value:#010x}, computed {crc:#010x}"
        )));
    }
    cx.emit(node);
    Ok(())
}

/// Free blocks from `block` (at least one), at most `MAX_RUN` of them.
async fn free_run(cx: &Cx, p: &Params, block: u64) -> u64 {
    let end = p.blocks.min(block.saturating_add(MAX_RUN));
    let mut at = block;
    while at < end && !p.used(at) {
        at = at.saturating_add(1);
        if at.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
    }
    at.saturating_sub(block).max(1)
}

fn run_name(first: u64, end: u64) -> String {
    let last = end.saturating_sub(1);
    if last <= first {
        format!("Block {first}")
    } else {
        format!("Blocks {first}–{last}")
    }
}
