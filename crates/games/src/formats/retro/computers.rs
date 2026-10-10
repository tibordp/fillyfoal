//! Home-computer disk, tape and cartridge images.

use crate::bytes::{to_u64, u16_le, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

/// PETSCII text as found in CBM directories (0xa0 is padding).
fn petscii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|&&b| b != 0xa0)
        .map(|&b| match b {
            0x20..=0x5f => char::from(b),
            0xc1..=0xda => char::from(b.saturating_sub(0x80)),
            _ => '?',
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Commodore 1541 disk image (D64)

const D64_SIZES: [u64; 4] = [174_848, 175_531, 196_608, 197_376];

fn d64_probe(h: &Head<'_>) -> bool {
    D64_SIZES.contains(&h.len)
}

declare_format!(pub D64 = "d64", "Commodore 1541 disk image", ["d64"],
    "application/x-d64", Probe::Custom(d64_probe), d64);

/// Byte offset of a track/sector on a 1541 disk.
fn d64_offset(track: u8, sector: u8) -> Option<u64> {
    if track == 0 || track > 40 {
        return None;
    }
    let sectors = |t: u8| -> u64 {
        match t {
            1..=17 => 21,
            18..=24 => 19,
            25..=30 => 18,
            _ => 17,
        }
    };
    if u64::from(sector) >= sectors(track) {
        return None;
    }
    let before: u64 = (1..track).map(sectors).sum();
    Some(before.saturating_add(sector.into()).saturating_mul(256))
}

const CBM_TYPES: EnumTable = &[(0, "DEL"), (1, "SEQ"), (2, "PRG"), (3, "USR"), (4, "REL")];

async fn d64(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let bam_at = d64_offset(18, 0).unwrap_or(0);
    let bam = file.sub(bam_at, 256);
    let data = cx.read(bam).await?;
    let name = petscii(data.get(0x90..0xa0).unwrap_or_default());
    let id = petscii(data.get(0xa2..0xa4).unwrap_or_default());
    let mut node = Node::new("BAM and disk header").span(bam);
    if data.get(2) != Some(&0x41) {
        node = node.diag(Diagnostic::warning("DOS version byte is not 'A'"));
    }
    cx.emit(node);
    cx.emit(
        Node::new("Disk name")
            .span(bam.sub(0x90, 16))
            .value(Value::Text(name.clone())),
    );
    cx.emit(
        Node::new("Disk ID")
            .span(bam.sub(0xa2, 2))
            .value(Value::Text(id.clone())),
    );
    cx.emit(Node::new("Directory").lazy(d64_directory, input));
    cx.annotate(format!("{name:?}, ID {id}"));
    Ok(())
}

async fn d64_directory(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (mut track, mut sector) = (18u8, 1u8);
    let mut visited = Vec::new();
    while track != 0 {
        if visited.contains(&(track, sector)) || visited.len() > 100 {
            return Err(Diagnostic::malformed("directory chain loops"));
        }
        visited.push((track, sector));
        let at = d64_offset(track, sector)
            .ok_or_else(|| Diagnostic::malformed("bad directory track/sector"))?;
        let block = cx.read(file.sub(at, 256)).await?;
        for slot in 0..8usize {
            let e = slot.saturating_mul(32);
            let kind = block.get(e.saturating_add(2)).copied().unwrap_or(0);
            if kind == 0 {
                continue;
            }
            let name = petscii(
                block
                    .get(e.saturating_add(5)..e.saturating_add(21))
                    .unwrap_or_default(),
            );
            let blocks = u16_le(&block, e.saturating_add(30)).unwrap_or(0);
            let start = (
                block.get(e.saturating_add(3)).copied().unwrap_or(0),
                block.get(e.saturating_add(4)).copied().unwrap_or(0),
            );
            let type_name = lookup(CBM_TYPES, (kind & 7).into()).unwrap_or("???");
            let entry = file.sub(at.saturating_add(to_u64(e)), 32);
            cx.push(
                Node::new(name)
                    .span(entry)
                    .summary(format!(
                        "{type_name}, {blocks} blocks{}",
                        if kind & 0x80 == 0 {
                            " (not closed)"
                        } else {
                            ""
                        }
                    ))
                    .lazy(d64_file, (input, start)),
            )
            .await;
        }
        track = block.first().copied().unwrap_or(0);
        sector = block.get(1).copied().unwrap_or(0);
    }
    Ok(())
}

/// A file is a chain of sectors; bytes 0..2 of each link to the next. The
/// chain becomes a piecewise source, so the file is readable in one piece.
async fn d64_file(cx: Cx, (input, start): (Input, (u8, u8))) -> Result<()> {
    let file = input.span;
    let (mut track, mut sector) = start;
    let mut pieces = Vec::new();
    let mut visited = Vec::new();
    while track != 0 {
        if visited.contains(&(track, sector)) || visited.len() > 800 {
            cx.diag(Diagnostic::malformed("sector chain loops"));
            break;
        }
        visited.push((track, sector));
        let Some(at) = d64_offset(track, sector) else {
            cx.diag(Diagnostic::malformed(format!(
                "bad track/sector {track}/{sector}"
            )));
            break;
        };
        let link = cx.read(file.sub(at, 2)).await?;
        let (next_t, next_s) = (
            link.first().copied().unwrap_or(0),
            link.get(1).copied().unwrap_or(0),
        );
        // In the last sector, the second byte is the index of the last byte used.
        let used = if next_t == 0 {
            u64::from(next_s).saturating_sub(1)
        } else {
            254
        };
        pieces.push(file.sub(at.saturating_add(2), used));
        cx.checkpoint().await;
        track = next_t;
        sector = next_s;
    }
    let chain = cx.add_pieces(
        Origin {
            parent: file.sub(d64_offset(start.0, start.1).unwrap_or(0), 256),
            transform: "cbm-chain",
        },
        pieces,
    )?;
    cx.emit(
        Node::new("Load address")
            .span(chain.sub(0, 2))
            .value(Value::UInt {
                value: u16_le(&cx.read_avail(chain.sub(0, 2)).await?, 0)
                    .unwrap_or(0)
                    .into(),
                bits: 16,
                radix: crate::value::Radix::Hex,
            }),
    );
    cx.emit(Node::new("Contents").span(chain).summary(format!(
        "{} bytes in {} sectors",
        chain.len,
        visited.len()
    )));
    Ok(())
}

// ---------------------------------------------------------------------------
// Commodore T64 tape image and CRT cartridge

declare_format!(pub T64 = "t64", "Commodore 64 tape image (T64)", ["t64"],
    "application/x-t64", Probe::Magic(&[(0, b"C64 tape image file"), (0, b"C64S tape file"), (0, b"C64S tape image file")]), t64);

record! {
    pub struct T64Header {
        signature: ascii[32] "Signature",
        version: u16 "Version" .hex(),
        max_entries: u16 "Directory entries",
        used: u16 "Used entries",
        _unused: u16 "Unused",
        name: ascii[24] "Tape name",
    }
}

record! {
    pub struct T64Entry {
        kind: u8 "Entry type" .enumeration(&[(0, "free"), (1, "normal tape file"), (3, "memory snapshot")]),
        file_type: u8 "C64 file type" .hex(),
        start: u16 "Start address" .hex(),
        end: u16 "End address" .hex(),
        _unused: u16 "Unused",
        offset: u32 "Data offset" .hex(),
        _unused2: u32 "Unused",
        name: bytes[16] "File name",
    }
}

async fn t64(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: T64Header = read_record(&cx, file.sub(0, T64Header::SIZE), LE).await?;
    cx.emit(T64Header::node("Header", file.sub(0, T64Header::SIZE), LE));
    cx.set_count(Count::AtLeast(u64::from(h.max_entries)));
    for i in 0..u64::from(h.max_entries.min(1000)) {
        let span = file.sub(0x40u64.saturating_add(i.saturating_mul(32)), 32);
        let e: T64Entry = read_record(&cx, span, LE).await?;
        if e.kind == 0 {
            continue;
        }
        let len = u64::from(e.end.saturating_sub(e.start));
        let name = petscii(&e.name);
        cx.push(
            T64Entry::node(name.trim_end().to_owned(), span, LE)
                .summary(format!("${:04x}-${:04x}", e.start, e.end))
                .target(file.sub(e.offset.into(), len)),
        )
        .await;
    }
    cx.annotate(format!("{:?}, {} files", h.name.trim_end(), h.used));
    Ok(())
}

declare_format!(pub CRT = "crt", "Commodore 64 cartridge image", ["crt"],
    "application/x-c64-cartridge", Probe::Magic(&[(0, b"C64 CARTRIDGE   ")]), crt);

const CRT_TYPES: EnumTable = &[
    (0, "Normal cartridge"),
    (1, "Action Replay"),
    (2, "KCS Power Cartridge"),
    (3, "Final Cartridge III"),
    (4, "Simons' BASIC"),
    (5, "Ocean type 1"),
    (6, "Expert Cartridge"),
    (7, "Fun Play"),
    (8, "Super Games"),
    (9, "Atomic Power"),
    (10, "Epyx Fastload"),
    (11, "Westermann Learning"),
    (12, "Rex Utility"),
    (13, "Final Cartridge I"),
    (14, "Magic Formel"),
    (15, "C64 Game System"),
    (16, "Warp Speed"),
    (17, "Dinamic"),
    (18, "Zaxxon"),
    (19, "Magic Desk"),
    (20, "Super Snapshot V5"),
    (21, "Comal-80"),
    (32, "EasyFlash"),
    (60, "GMod2"),
];

record! {
    pub struct CrtHeader {
        signature: ascii[16] "Signature",
        length: u32 "Header length" .hex(),
        version: u16 "Version" .hex(),
        hardware: u16 "Hardware type" .enumeration(CRT_TYPES),
        exrom: u8 "EXROM line",
        game: u8 "GAME line",
        _reserved: bytes[6] "Reserved",
        name: ascii[32] "Cartridge name",
    }
}

record! {
    pub struct CrtChip {
        signature: ascii[4] "Signature",
        length: u32 "Packet length" .hex(),
        kind: u16 "Chip type" .enumeration(&[(0, "ROM"), (1, "RAM"), (2, "Flash ROM")]),
        bank: u16 "Bank",
        load: u16 "Load address" .hex(),
        size: u16 "Image size" .hex(),
    }
}

async fn crt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: CrtHeader = read_record(&cx, file.sub(0, CrtHeader::SIZE), BE).await?;
    cx.emit(CrtHeader::node("Header", file.sub(0, CrtHeader::SIZE), BE));
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(h.length.into());
    while cur.remaining() >= CrtChip::SIZE {
        let start = cur.pos();
        let (chip, span) = cur.record::<CrtChip>().await?;
        if chip.signature != "CHIP" || chip.length < 16 {
            cx.diag(Diagnostic::malformed("expected a CHIP packet").at(span));
            break;
        }
        cur.seek(start.saturating_add(chip.length.into()));
        cx.push(
            CrtChip::node(format!("Bank {}", chip.bank), cur.since(start), BE)
                .summary(format!("${:04x}, {} bytes", chip.load, chip.size)),
        )
        .await;
    }
    let hardware = lookup(CRT_TYPES, h.hardware.into()).unwrap_or("unknown hardware");
    cx.annotate(format!("{:?}, {hardware}", h.name.trim_end()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Amiga: ADF disk images and hunk executables

fn adf_probe(h: &Head<'_>) -> bool {
    matches!(h.len, 901_120 | 1_802_240) && h.starts_with(b"DOS")
}

declare_format!(pub ADF = "adf", "Amiga disk image", ["adf"],
    "application/x-amiga-disk-format", Probe::Custom(adf_probe), adf);

const ADF_DOS: EnumTable = &[
    (0, "OFS"),
    (1, "FFS"),
    (2, "OFS international"),
    (3, "FFS international"),
    (4, "OFS dircache"),
    (5, "FFS dircache"),
];

async fn adf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let boot = cx.block(file.sub(0, 12)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &boot, BE);
    f.ascii("Disk type", 3).emit()?;
    let dos = f.u8("Filesystem").enumeration(ADF_DOS).emit()?;
    f.u32("Boot block checksum").hex().emit()?;
    let root = f.u32("Root block").emit()?;
    let root_span = file.sub(u64::from(root).saturating_mul(512), 512);
    let data = cx.read(root_span).await?;
    let name_len = usize::from(data.get(432).copied().unwrap_or(0).min(30));
    let name = String::from_utf8_lossy(
        data.get(433..433usize.saturating_add(name_len))
            .unwrap_or_default(),
    )
    .into_owned();
    cx.emit(
        Node::new("Root block")
            .span(root_span)
            .summary(format!("volume {name:?}"))
            .lazy(adf_dir, (file, root)),
    );
    let fs = lookup(ADF_DOS, dos.into()).unwrap_or("unknown");
    cx.annotate(format!("{name:?}, {fs}, {} KiB", file.len / 1024));
    Ok(())
}

/// Lists a directory block's hash table (72 slots, each a chain of headers).
async fn adf_dir(cx: Cx, (file, block): (Span, u32)) -> Result<()> {
    let dir = cx
        .read(file.sub(u64::from(block).saturating_mul(512), 512))
        .await?;
    let mut seen = Vec::new();
    for slot in 0..72usize {
        let mut next = u32_be(&dir, 24usize.saturating_add(slot.saturating_mul(4))).unwrap_or(0);
        while next != 0 {
            if seen.contains(&next) || seen.len() > 4096 {
                return Err(Diagnostic::malformed("directory hash chain loops"));
            }
            seen.push(next);
            let span = file.sub(u64::from(next).saturating_mul(512), 512);
            let header = cx.read(span).await?;
            let sec_type = u32_be(&header, 508).unwrap_or(0) as i32;
            let size = u32_be(&header, 324).unwrap_or(0);
            let len = usize::from(header.get(432).copied().unwrap_or(0).min(30));
            let name = String::from_utf8_lossy(
                header
                    .get(433..433usize.saturating_add(len))
                    .unwrap_or_default(),
            )
            .into_owned();
            let node = Node::new(name).span(span);
            let node = if sec_type == 2 {
                node.summary("directory")
                    .lazy(crate::expander!(self::adf_dir: (Span, u32)), (file, next))
            } else {
                node.summary(format!("{size} bytes"))
            };
            cx.push(node).await;
            next = u32_be(&header, 496).unwrap_or(0);
        }
    }
    Ok(())
}

declare_format!(pub AMIGA_HUNK = "amiga-hunk", "Amiga executable (hunk format)", [],
    "application/x-amiga-executable", Probe::Magic(&[(0, b"\x00\x00\x03\xf3")]), amiga_hunk);

const HUNK_TYPES: EnumTable = &[
    (0x3e7, "HUNK_UNIT"),
    (0x3e8, "HUNK_NAME"),
    (0x3e9, "HUNK_CODE"),
    (0x3ea, "HUNK_DATA"),
    (0x3eb, "HUNK_BSS"),
    (0x3ec, "HUNK_RELOC32"),
    (0x3ed, "HUNK_RELOC16"),
    (0x3ee, "HUNK_RELOC8"),
    (0x3ef, "HUNK_EXT"),
    (0x3f0, "HUNK_SYMBOL"),
    (0x3f1, "HUNK_DEBUG"),
    (0x3f2, "HUNK_END"),
    (0x3f3, "HUNK_HEADER"),
    (0x3f5, "HUNK_OVERLAY"),
    (0x3f6, "HUNK_BREAK"),
    (0x3f7, "HUNK_DREL32"),
    (0x3f8, "HUNK_DREL16"),
    (0x3f9, "HUNK_DREL8"),
    (0x3fa, "HUNK_LIB"),
    (0x3fb, "HUNK_INDEX"),
    (0x3fc, "HUNK_RELOC32SHORT"),
];

async fn amiga_hunk(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, BE);
    let mut count = 0u32;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let id = cur.u32().await? & 0x3fff_ffff;
        let name =
            lookup(HUNK_TYPES, id.into()).map_or_else(|| format!("hunk {id:#x}"), str::to_owned);
        match id {
            0x3f3 => {
                // Resident library names, then table size and hunk sizes.
                loop {
                    let n = cur.u32().await?;
                    if n == 0 {
                        break;
                    }
                    cur.skip(u64::from(n).saturating_mul(4));
                }
                let _table = cur.u32().await?;
                let first = cur.u32().await?;
                let last = cur.u32().await?;
                count = last.saturating_sub(first).saturating_add(1);
                cur.skip(u64::from(count).saturating_mul(4));
            }
            0x3e9 | 0x3ea | 0x3f1 | 0x3e8 | 0x3e7 => {
                let longs = cur.u32().await? & 0x3fff_ffff;
                cur.skip(u64::from(longs).saturating_mul(4));
            }
            0x3eb => {
                cur.skip(4);
            }
            0x3ec | 0x3ed | 0x3ee | 0x3f7 | 0x3f8 | 0x3f9 => loop {
                let n = cur.u32().await?;
                if n == 0 {
                    break;
                }
                cur.skip(u64::from(n).saturating_add(1).saturating_mul(4));
            },
            0x3fc => loop {
                let n = u32::from(cur.u16().await?);
                if n == 0 {
                    break;
                }
                cur.skip(u64::from(n).saturating_add(1).saturating_mul(2));
            },
            0x3f0 => loop {
                let n = cur.u32().await? & 0x00ff_ffff;
                if n == 0 {
                    break;
                }
                cur.skip(u64::from(n).saturating_add(1).saturating_mul(4));
            },
            0x3f2 => {}
            _ => {
                cx.push(
                    Node::new(name)
                        .span(cur.since(start))
                        .diag(Diagnostic::unsupported("hunk type")),
                )
                .await;
                break;
            }
        }
        if id == 0x3fc && !cur.pos().is_multiple_of(4) {
            cur.skip(2);
        }
        cx.push(Node::new(name).span(cur.since(start))).await;
    }
    cx.annotate(format!("Amiga executable, {count} hunks"));
    Ok(())
}

// ---------------------------------------------------------------------------
// ZX Spectrum TZX tapes

declare_format!(pub TZX = "tzx", "ZX Spectrum tape image (TZX)", ["tzx", "cdt"],
    "application/x-spectrum-tzx", Probe::Magic(&[(0, b"ZXTape!\x1a")]), tzx);

const TZX_BLOCKS: EnumTable = &[
    (0x10, "Standard speed data"),
    (0x11, "Turbo speed data"),
    (0x12, "Pure tone"),
    (0x13, "Pulse sequence"),
    (0x14, "Pure data"),
    (0x15, "Direct recording"),
    (0x18, "CSW recording"),
    (0x19, "Generalized data"),
    (0x20, "Pause / stop the tape"),
    (0x21, "Group start"),
    (0x22, "Group end"),
    (0x23, "Jump to block"),
    (0x24, "Loop start"),
    (0x25, "Loop end"),
    (0x26, "Call sequence"),
    (0x27, "Return from sequence"),
    (0x28, "Select block"),
    (0x2a, "Stop the tape if in 48K mode"),
    (0x2b, "Set signal level"),
    (0x30, "Text description"),
    (0x31, "Message"),
    (0x32, "Archive info"),
    (0x33, "Hardware type"),
    (0x35, "Custom info"),
    (0x5a, "Glue"),
];

async fn tzx(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, LE);
    cx.emit(Node::new("Signature").span(cur.span(10)));
    let version = cur.peek(10).await?;
    cur.skip(10);
    let mut blocks = 0u32;
    while !cur.at_end() {
        let start = cur.pos();
        let id = cur.u8().await?;
        // Each block's length is determined by fields at fixed positions.
        let len_at = |rel: u64, width: u64, mul: u64, extra: u64| (rel, width, mul, extra);
        let (rel, width, mul, extra) = match id {
            0x10 => len_at(2, 2, 1, 4),
            0x11 => len_at(15, 3, 1, 18),
            0x12 => len_at(0, 0, 0, 4),
            0x13 => len_at(0, 1, 2, 1),
            0x14 => len_at(7, 3, 1, 10),
            0x15 => len_at(5, 3, 1, 8),
            0x18 | 0x19 => len_at(0, 4, 1, 4),
            0x20 | 0x23 | 0x24 => len_at(0, 0, 0, 2),
            0x21 | 0x30 => len_at(0, 1, 1, 1),
            0x22 | 0x25 | 0x27 => len_at(0, 0, 0, 0),
            0x26 => len_at(0, 2, 2, 2),
            0x28 | 0x32 => len_at(0, 2, 1, 2),
            0x2a => len_at(0, 0, 0, 4),
            0x2b => len_at(0, 0, 0, 5),
            0x31 => len_at(1, 1, 1, 2),
            0x33 => len_at(0, 1, 3, 1),
            0x35 => len_at(16, 4, 1, 20),
            0x5a => len_at(0, 0, 0, 9),
            _ => len_at(0, 4, 1, 4),
        };
        let field = cur.peek(rel.saturating_add(width)).await?;
        let mut n = 0u64;
        for i in 0..crate::bytes::to_usize(width) {
            let byte = field
                .get(crate::bytes::to_usize(rel).saturating_add(i))
                .copied()
                .unwrap_or(0);
            n |= u64::from(byte)
                .checked_shl(u32::try_from(i.saturating_mul(8)).unwrap_or(0))
                .unwrap_or(0);
        }
        cur.skip(n.saturating_mul(mul).saturating_add(extra));
        let name =
            lookup(TZX_BLOCKS, id.into()).map_or_else(|| format!("Block {id:#04x}"), str::to_owned);
        let mut node = Node::new(name).span(cur.since(start)).value(Value::UInt {
            value: id.into(),
            bits: 8,
            radix: crate::value::Radix::Hex,
        });
        if id == 0x30 {
            let text = cx
                .read_avail(input.span.sub(start.saturating_add(2), n))
                .await?;
            node = node.summary(String::from_utf8_lossy(&text).into_owned());
        }
        if lookup(TZX_BLOCKS, id.into()).is_none() {
            node = node.diag(Diagnostic::note(
                "unknown block; length taken from the extension rule",
            ));
        }
        cx.push(node).await;
        blocks = blocks.saturating_add(1);
    }
    cx.annotate(format!(
        "TZX {}.{}, {blocks} blocks",
        version.get(8).copied().unwrap_or(0),
        version.get(9).copied().unwrap_or(0)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Amstrad CPC disk images (DSK / EDSK)

declare_format!(pub CPC_DSK = "cpc-dsk", "Amstrad CPC disk image", ["dsk"],
    "application/x-cpc-dsk", Probe::Magic(&[(0, b"MV - CPC"), (0, b"EXTENDED CPC DSK File")]), cpc_dsk);

async fn cpc_dsk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let info = cx.read(file.sub(0, 256)).await?;
    let extended = info.starts_with(b"EXTENDED");
    let tracks = info.get(0x30).copied().unwrap_or(0);
    let sides = info.get(0x31).copied().unwrap_or(0);
    let creator = crate::text::until_nul(info.get(0x22..0x30).unwrap_or_default());
    cx.emit(
        Node::new("Disk information block")
            .span(file.sub(0, 256))
            .summary(creator.trim().to_owned()),
    );
    let count = usize::from(tracks).saturating_mul(sides.max(1).into());
    cx.set_count(Count::Exact(to_u64(count).saturating_add(1)));
    let mut at = 256u64;
    for i in 0..count {
        let size = if extended {
            u64::from(info.get(0x34usize.saturating_add(i)).copied().unwrap_or(0))
                .saturating_mul(256)
        } else {
            u64::from(u16_le(&info, 0x32).unwrap_or(0))
        };
        if size == 0 {
            continue;
        }
        let span = file.sub(at, size);
        let header = cx.read_avail(span.sub(0, 0x18)).await?;
        let sectors = header.get(0x15).copied().unwrap_or(0);
        cx.push(
            Node::new(format!(
                "Track {} side {}",
                header.get(0x10).copied().unwrap_or(0),
                header.get(0x11).copied().unwrap_or(0)
            ))
            .span(span)
            .summary(format!("{sectors} sectors")),
        )
        .await;
        at = at.saturating_add(size);
    }
    cx.annotate(format!(
        "{}, {tracks} tracks, {sides} side(s)",
        if extended {
            "Extended DSK"
        } else {
            "Standard DSK"
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Atari ST (MSA) and Atari 8-bit (ATR) disk images

declare_format!(pub MSA = "msa", "Atari ST disk image (MSA)", ["msa"],
    "application/x-msa", Probe::Magic(&[(0, b"\x0e\x0f")]), msa);

record! {
    pub struct MsaHeader {
        magic: u16 "Magic" .hex(),
        sectors: u16 "Sectors per track",
        sides: u16 "Sides (0 = single)",
        start: u16 "Start track",
        end: u16 "End track",
    }
}

async fn msa(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: MsaHeader = read_record(&cx, file.sub(0, MsaHeader::SIZE), BE).await?;
    cx.emit(MsaHeader::node("Header", file.sub(0, MsaHeader::SIZE), BE));
    let full = u64::from(h.sectors).saturating_mul(512);
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(MsaHeader::SIZE);
    let tracks = u32::from(h.end.saturating_sub(h.start).saturating_add(1))
        .saturating_mul(u32::from(h.sides).saturating_add(1));
    for i in 0..tracks {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let len = cur.u16().await?;
        cur.skip(len.into());
        cx.push(
            Node::new(format!("Track {i}"))
                .span(cur.since(start))
                .summary(if u64::from(len) < full {
                    "RLE compressed"
                } else {
                    "uncompressed"
                }),
        )
        .await;
    }
    cx.annotate(format!(
        "{} sectors/track, tracks {}-{}, {} side(s)",
        h.sectors,
        h.start,
        h.end,
        h.sides.saturating_add(1)
    ));
    Ok(())
}

declare_format!(pub ATR = "atr", "Atari 8-bit disk image (ATR)", ["atr"],
    "application/x-atari-atr", Probe::Magic(&[(0, b"\x96\x02")]), atr);

record! {
    pub struct AtrHeader {
        magic: u16 "Magic" .hex(),
        paragraphs: u16 "Image size (16-byte paragraphs, low)",
        sector_size: u16 "Sector size",
        paragraphs_high: u8 "Image size (high byte)",
        crc: u32 "CRC" .hex(),
        _unused: u32 "Unused",
        flags: u8 "Flags" .hex(),
    }
}

async fn atr(cx: Cx, input: Input) -> Result<()> {
    let h: AtrHeader = emit_record(&cx, input.span.sub(0, 16), LE).await?;
    let size = (u64::from(h.paragraphs_high) << 16 | u64::from(h.paragraphs)).saturating_mul(16);
    cx.emit(Node::new("Sectors").span(input.span.tail(16)));
    cx.annotate(format!("{} bytes, {}-byte sectors", size, h.sector_size));
    Ok(())
}

// ---------------------------------------------------------------------------
// Apple II: WOZ and 2IMG

declare_format!(pub WOZ = "woz", "Apple II disk image (WOZ)", ["woz"],
    "application/x-apple2-woz", Probe::Magic(&[(0, b"WOZ1\xff\n\r\n"), (0, b"WOZ2\xff\n\r\n")]), woz);

async fn woz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Header").span(file.sub(0, 12)));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    let mut info = None;
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = cur.u32().await?;
        let data = cur.span(len.into());
        cur.skip(len.into());
        let mut node = Node::new(id.clone())
            .span(cur.since(start))
            .summary(format!("{len} bytes"));
        if id == "INFO" {
            let bytes = cx.read_avail(data.sub(0, 60)).await?;
            let disk = match bytes.get(1) {
                Some(1) => "5.25\"",
                Some(2) => "3.5\"",
                _ => "unknown size",
            };
            let creator = String::from_utf8_lossy(bytes.get(5..37).unwrap_or_default())
                .trim()
                .to_owned();
            node = node.summary(format!("{disk} disk, created by {creator}"));
            info = Some(disk);
        }
        if id == "META" {
            let text = cx.read_avail(data.sub(0, 4096)).await?;
            node = node.lazy(woz_meta, String::from_utf8_lossy(&text).into_owned());
        }
        cx.push(node).await;
    }
    cx.annotate(format!("WOZ, {}", info.unwrap_or("no INFO chunk")));
    Ok(())
}

async fn woz_meta(cx: Cx, text: String) -> Result<()> {
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('\t') {
            cx.push(Node::new(k.to_owned()).value(Value::Text(v.to_owned())))
                .await;
        }
    }
    Ok(())
}

declare_format!(pub TWO_IMG = "2mg", "Apple II universal disk image (2IMG)", ["2mg", "2img"],
    "application/x-apple2-2img", Probe::Magic(&[(0, b"2IMG")]), two_img);

record! {
    pub struct TwoImgHeader {
        magic: ascii[4] "Magic",
        creator: ascii[4] "Creator",
        header_size: u16 "Header size",
        version: u16 "Version",
        format: u32 "Image format" .enumeration(&[(0, "DOS 3.3 order"), (1, "ProDOS order"), (2, "NIB data")]),
        flags: u32 "Flags" .hex(),
        blocks: u32 "ProDOS blocks",
        data_offset: u32 "Data offset" .hex(),
        data_length: u32 "Data length" .hex(),
        comment_offset: u32 "Comment offset" .hex(),
        comment_length: u32 "Comment length",
        creator_offset: u32 "Creator data offset" .hex(),
        creator_length: u32 "Creator data length",
    }
}

async fn two_img(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: TwoImgHeader = emit_record(&cx, file.sub(0, TwoImgHeader::SIZE), LE).await?;
    cx.emit(Node::new("Disk data").span(file.sub(h.data_offset.into(), h.data_length.into())));
    if h.comment_length > 0 {
        let span = file.sub(h.comment_offset.into(), h.comment_length.into());
        let text = cx.read_avail(span).await?;
        cx.emit(
            Node::new("Comment")
                .span(span)
                .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
        );
    }
    cx.annotate(format!("{} blocks, created by {}", h.blocks, h.creator));
    Ok(())
}

// ---------------------------------------------------------------------------
// BBC Micro / Acorn Electron UEF tapes (chunks)

declare_format!(pub UEF = "uef", "Acorn tape image (UEF)", ["uef"],
    "application/x-uef", Probe::Magic(&[(0, b"UEF File!\0")]), uef);

async fn uef(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Header").span(file.sub(0, 12)));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    while cur.remaining() >= 6 {
        let start = cur.pos();
        let id = cur.u16().await?;
        let len = cur.u32().await?;
        cur.skip(len.into());
        cx.push(
            Node::new(format!("Chunk {id:#06x}"))
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        )
        .await;
    }
    let version = cx.read_avail(file.sub(10, 2)).await?;
    cx.annotate(format!(
        "UEF {}.{}",
        version.get(1).copied().unwrap_or(0),
        version.first().copied().unwrap_or(0)
    ));
    Ok(())
}
