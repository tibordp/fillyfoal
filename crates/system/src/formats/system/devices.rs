//! Embedded-device filesystems and firmware, console containers, and
//! Windows memory images.

use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::fmt::plural;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// romfs

declare_format!(pub ROMFS = "romfs", "Linux ROM file system", ["romfs", "img"], "application/x-romfs",
    Probe::Magic(&[(0, b"-rom1fs-")]), romfs);

const ROMFS_TYPES: [&str; 8] = [
    "hard link",
    "directory",
    "file",
    "symlink",
    "block device",
    "char device",
    "socket",
    "fifo",
];

async fn romfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let size = u32_be(&head, 8).unwrap_or(0);
    let (name, name_span) = cx.cstr(file.sub(16, 256)).await?;
    cx.emit(
        Node::new("Superblock")
            .span(file.sub(0, 16))
            .summary(format!("{size} bytes")),
    );
    cx.emit(
        Node::new("Volume name")
            .span(name_span)
            .value(Value::Text(name.clone())),
    );
    let first = 16u64.saturating_add(name_span.len.next_multiple_of(16));
    cx.emit(Node::new("/").lazy(romfs_dir, (input, first, 0u32)));
    cx.annotate(format!("romfs {name:?}, {size} bytes"));
    Ok(())
}

/// Lists the chain of file headers starting at `offset`.
async fn romfs_dir(cx: Cx, (input, mut offset, depth): (Input, u64, u32)) -> Result<()> {
    if depth > 32 {
        return Err(Diagnostic::limit("directories nested too deeply"));
    }
    let file = input.span;
    let mut seen = std::collections::BTreeSet::new();
    while offset != 0 && offset < file.len {
        if seen.contains(&offset) || seen.len() > 100_000 {
            return Err(Diagnostic::malformed("file header chain loops"));
        }
        seen.insert(offset);
        let head = cx.read(file.sub(offset, 16)).await?;
        let next = u32_be(&head, 0).unwrap_or(0);
        let spec = u32_be(&head, 4).unwrap_or(0);
        let size = u64::from(u32_be(&head, 8).unwrap_or(0));
        let (name, name_span) = cx.cstr(file.sub(offset.saturating_add(16), 256)).await?;
        let data = offset
            .saturating_add(16)
            .saturating_add(name_span.len.next_multiple_of(16));
        let kind = usize::try_from(next & 7).unwrap_or(0);
        let header = file.sub(offset, data.saturating_sub(offset));
        let node = match kind {
            1 if name != "." && name != ".." => Node::new(format!("{name}/")).lazy(
                crate::expander!(self::romfs_dir: (Input, u64, u32)),
                (input, u64::from(spec), depth.saturating_add(1)),
            ),
            2 => embedded(name.clone(), input.nested(file.sub(data, size)))
                .summary(format!("{size} bytes")),
            _ => Node::new(name.clone()).summary(ROMFS_TYPES.get(kind).copied().unwrap_or("?")),
        };
        if name != "." && name != ".." {
            cx.push(node.target(header)).await;
        }
        offset = u64::from(next & !15);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JFFS2, UBI, UBIFS (raw flash images)

fn jffs2_probe(h: &Head<'_>) -> bool {
    (h.at(0, b"\x85\x19")
        && u16_le(h.data, 2).is_some_and(|t| t & 0xff00 == 0xe000 || t & 0xff00 == 0x2000))
        || (h.at(0, b"\x19\x85")
            && u16_be(h.data, 2).is_some_and(|t| t & 0xff00 == 0xe000 || t & 0xff00 == 0x2000))
}

declare_format!(pub JFFS2 = "jffs2", "JFFS2 flash file system", ["jffs2", "img"], "application/x-jffs2",
    Probe::Custom(jffs2_probe), jffs2);

const JFFS2_NODES: EnumTable = &[
    (0xe001, "DIRENT"),
    (0xe002, "INODE"),
    (0x2003, "CLEANMARKER"),
    (0x2004, "PADDING"),
    (0x2006, "SUMMARY"),
    (0xe008, "XATTR"),
    (0xe009, "XREF"),
];

async fn jffs2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let little = cx.read(file.sub(0, 2)).await? == b"\x85\x19";
    let endian = if little { LE } else { BE };
    let mut cur = Cursor::new(&cx, file, endian);
    let (mut dirents, mut inodes) = (0u32, 0u32);
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let magic = cur.u16().await?;
        if magic != 0x1985 {
            // Erased flash (0xff) or padding: skip to the next 4-byte boundary.
            cur.seek(start.saturating_add(4));
            continue;
        }
        let kind = cur.u16().await?;
        let len = u64::from(cur.u32().await?);
        if len < 12 {
            cur.seek(start.saturating_add(4));
            continue;
        }
        let mut node = Node::new(
            lookup(JFFS2_NODES, kind.into()).map_or_else(|| format!("{kind:#06x}"), str::to_owned),
        )
        .span(file.sub(start, len));
        if kind == 0xe001 {
            dirents = dirents.saturating_add(1);
            let d = cx.read_avail(file.sub(start, 40.min(len))).await?;
            let nsize = usize::from(d.get(28).copied().unwrap_or(0));
            let name = cx
                .read_avail(file.sub(start.saturating_add(40), nsize as u64))
                .await?;
            node = node.summary(String::from_utf8_lossy(&name).into_owned());
        } else if kind == 0xe002 {
            inodes = inodes.saturating_add(1);
        }
        cx.progress_in(file, file.offset.saturating_add(start));
        cx.push(node).await;
        cur.seek(start.saturating_add(len).next_multiple_of(4));
    }
    cx.annotate(format!(
        "JFFS2 ({} endian), {dirents} directory entries, {inodes} inode nodes",
        if little { "little" } else { "big" }
    ));
    Ok(())
}

declare_format!(pub UBI = "ubi", "UBI flash image", ["ubi", "img"], "application/x-ubi",
    Probe::Magic(&[(0, b"UBI#")]), ubi);

record! {
    pub struct UbiEcHeader {
        magic: ascii[4] "Magic",
        version: u8 "Version",
        _padding: bytes[3] "Padding",
        erase_counter: u64 "Erase counter",
        vid_offset: u32 "VID header offset" .hex(),
        data_offset: u32 "Data offset" .hex(),
        image_seq: u32 "Image sequence number" .hex(),
        _padding2: bytes[32] "Padding",
        crc: u32 "Header CRC" .hex(),
    }
}

async fn ubi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: UbiEcHeader = read_record(&cx, file.sub(0, UbiEcHeader::SIZE), BE).await?;
    cx.emit(UbiEcHeader::node(
        "Erase counter header",
        file.sub(0, UbiEcHeader::SIZE),
        BE,
    ));
    // Find the eraseblock size: the next "UBI#" at a power of two.
    let mut peb = 0u64;
    for shift in 14..=21u32 {
        let size = 1u64 << shift;
        if size >= file.len {
            break;
        }
        if cx.read_avail(file.sub(size, 4)).await? == b"UBI#" {
            peb = size;
            break;
        }
    }
    let vid = cx.read_avail(file.sub(h.vid_offset.into(), 64)).await?;
    if vid.starts_with(b"UBI!") {
        cx.emit(
            Node::new("Volume ID header")
                .span(file.sub(h.vid_offset.into(), 64))
                .summary(format!(
                    "volume {}, LEB {}",
                    u32_be(&vid, 8).unwrap_or(0),
                    u32_be(&vid, 12).unwrap_or(0)
                )),
        );
    }
    let blocks = file.len.checked_div(peb).unwrap_or(1);
    let first = if peb > 0 { peb } else { file.len };
    let data = file.sub(
        h.data_offset.into(),
        first.saturating_sub(h.data_offset.into()),
    );
    cx.emit(embedded("Data (first eraseblock)", input.nested(data)));
    cx.annotate(format!(
        "UBI v{}, {} eraseblocks of {} KiB, image {:#x}",
        h.version,
        blocks,
        peb / 1024,
        h.image_seq
    ));
    Ok(())
}

fn ubifs_probe(h: &Head<'_>) -> bool {
    h.at(0, b"\x31\x18\x10\x06") && h.data.get(20) == Some(&6)
}

declare_format!(pub UBIFS = "ubifs", "UBIFS file system", ["ubifs", "img"], "application/x-ubifs",
    Probe::Custom(ubifs_probe), ubifs);

async fn ubifs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sb = cx.block(file.sub(0, 0x1000)).await?;
    let mut f = Fields::emitting(&cx, &sb, LE);
    f.u32("Magic").hex().emit()?;
    f.u32("CRC").hex().emit()?;
    f.u64("Sequence number").emit()?;
    f.u32("Node length").emit()?;
    f.u8("Node type").emit()?;
    f.u8("Group type").emit()?;
    f.bytes("Padding", 2).emit()?;
    f.bytes("Padding", 2).emit()?;
    f.u8("Key hash").emit()?;
    f.u8("Key format").emit()?;
    f.u32("Flags").hex().emit()?;
    let min_io = f.u32("Minimal I/O unit").emit()?;
    let leb = f.u32("LEB size").emit()?;
    let lebs = f.u32("LEB count").emit()?;
    f.u32("Max LEB count").emit()?;
    f.u64("Max bud bytes").emit()?;
    f.u32("Log LEBs").emit()?;
    f.u32("LPT LEBs").emit()?;
    f.u32("Orphan LEBs").emit()?;
    f.u32("Journal heads").emit()?;
    f.u32("Fanout").emit()?;
    f.u32("LSAVE count").emit()?;
    f.u32("Format version").emit()?;
    let compr = f
        .u16("Default compressor")
        .enumeration(&[(0, "none"), (1, "LZO"), (2, "zlib"), (3, "zstd")])
        .emit()?;
    cx.annotate(format!(
        "UBIFS, {lebs} LEBs of {} KiB, min I/O {min_io}, compressor {compr}",
        leb / 1024
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Broadcom TRX router firmware

declare_format!(pub TRX = "trx", "Broadcom TRX firmware", ["trx", "bin"], "application/x-trx",
    Probe::Magic(&[(0, b"HDR0")]), trx);

async fn trx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 28)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let len = f.u32("Length").emit()?;
    f.u32("CRC-32").checksum("CRC-32").emit()?;
    let flags = f.u16("Flags").hex().emit()?;
    let version = f.u16("Version").emit()?;
    let offsets = [
        f.u32("Partition 1 offset").hex().emit()?,
        f.u32("Partition 2 offset").hex().emit()?,
        f.u32("Partition 3 offset").hex().emit()?,
    ];
    let mut ends: Vec<u64> = offsets
        .iter()
        .skip(1)
        .map(|&o| u64::from(o))
        .filter(|&o| o != 0)
        .collect();
    ends.push(u64::from(len));
    for (i, &start) in offsets.iter().enumerate() {
        if start == 0 {
            continue;
        }
        let end = ends
            .get(i)
            .copied()
            .unwrap_or(u64::from(len))
            .max(start.into());
        let name = [
            "Loader / kernel",
            "Kernel / root filesystem",
            "Root filesystem",
        ]
        .get(i)
        .copied()
        .unwrap_or("Partition");
        cx.push(
            embedded(
                name,
                input.nested(file.sub(start.into(), end.saturating_sub(start.into()))),
            )
            .summary(format!("at {start:#x}")),
        )
        .await;
    }
    cx.annotate(format!("TRX v{version}, {len} bytes, flags {flags:#x}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Apple img3, Xbox 360 XEX, PlayStation 3 SELF and PKG

declare_format!(pub IMG3 = "img3", "Apple IMG3 firmware image", ["img3"], "application/x-apple-img3",
    Probe::Magic(&[(0, b"3gmI")]), img3);

async fn img3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Full size").emit()?;
    f.u32("Size without header").emit()?;
    f.u32("Signed size").emit()?;
    let ident = f.bytes("Identifier", 4).emit()?;
    let ident: String = ident.iter().rev().map(|&b| char::from(b)).collect();
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(20);
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let magic = cur.bytes(4).await?;
        let full = u64::from(cur.u32().await?);
        let data = u64::from(cur.u32().await?);
        let tag: String = magic.iter().rev().map(|&b| char::from(b)).collect();
        if full < 12 {
            break;
        }
        cur.seek(start.saturating_add(full));
        let body = file.sub(start.saturating_add(12), data);
        cx.push(
            embedded(
                tag,
                Input {
                    span: body,
                    nesting: input.nesting.saturating_add(1),
                    outer: file,
                },
            )
            .summary(format!("{data} bytes"))
            .target(cur.since(start)),
        )
        .await;
    }
    cx.annotate(format!("IMG3 {ident}"));
    Ok(())
}

declare_format!(pub XEX = "xex", "Xbox 360 executable", ["xex"], "application/x-xbox360-executable",
    Probe::Magic(&[(0, b"XEX2"), (0, b"XEX1"), (0, b"XEX%"), (0, b"XEX-")]), xex);

const XEX_HEADERS: EnumTable = &[
    (0x0000_02ff, "Resource info"),
    (0x0000_03ff, "File format info"),
    (0x0000_05ff, "Delta patch descriptor"),
    (0x0000_80ff, "Bounding path"),
    (0x0001_0100, "Original base address"),
    (0x0001_0201, "Entry point"),
    (0x0001_0001, "Image base address"),
    (0x0001_03ff, "Import libraries"),
    (0x0001_8002, "Checksum and timestamp"),
    (0x0001_83ff, "Original PE name"),
    (0x0002_00ff, "Static libraries"),
    (0x0002_0104, "TLS info"),
    (0x0002_0200, "Default stack size"),
    (0x0004_0006, "Execution info"),
    (0x0004_0310, "Game ratings"),
    (0x0004_0404, "LAN key"),
    (0x0004_05ff, "Xbox 360 logo"),
];

async fn xex(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let magic = f.ascii("Magic", 4).emit()?;
    f.u32("Module flags").hex().emit()?;
    let pe_offset = f.u32("PE data offset").hex().emit()?;
    f.u32("Reserved").emit()?;
    f.u32("Security info offset").hex().emit()?;
    let count = f.u32("Optional headers").emit()?;
    let mut name = None;
    for i in 0..count.min(64) {
        let at = 24u64.saturating_add(u64::from(i).saturating_mul(8));
        let entry = cx.read(file.sub(at, 8)).await?;
        let id = u32_be(&entry, 0).unwrap_or(0);
        let value = u32_be(&entry, 4).unwrap_or(0);
        if id == 0x0001_83ff
            && let Ok((n, _)) = cx
                .cstr(file.sub(u64::from(value).saturating_add(4), 256))
                .await
        {
            name = Some(n);
        }
        cx.push(
            Node::new(
                lookup(XEX_HEADERS, id.into()).map_or_else(|| format!("{id:#010x}"), str::to_owned),
            )
            .span(file.sub(at, 8))
            .value(Value::UInt {
                value: value.into(),
                bits: 32,
                radix: crate::value::Radix::Hex,
            }),
        )
        .await;
    }
    cx.emit(Node::new("PE image (encrypted/compressed)").span(file.tail(pe_offset.into())));
    cx.annotate(format!(
        "{magic}{}",
        name.map_or(String::new(), |n| format!(", {n}"))
    ));
    Ok(())
}

declare_format!(pub PS3_SELF = "ps3-self", "PlayStation 3 signed executable (SELF/SCE)", ["self", "sprx", "elf"], "application/x-ps3-self",
    Probe::Magic(&[(0, b"SCE\0")]), ps3_self);

const SCE_TYPES: EnumTable = &[(1, "SELF"), (2, "RVK"), (3, "PKG"), (4, "SPP")];

async fn ps3_self(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Header version").emit()?;
    f.u16("Key revision").hex().emit()?;
    let kind = f.u16("Type").enumeration(SCE_TYPES).emit()?;
    f.u32("Metadata offset").hex().emit()?;
    let header_len = f.u64("Header length").hex().emit()?;
    let data_len = f.u64("Data length").emit()?;
    cx.emit(Node::new("Encrypted data").span(file.sub(header_len, data_len)));
    cx.annotate(format!(
        "SCE {} container, {data_len} bytes of data",
        lookup(SCE_TYPES, kind.into()).unwrap_or("unknown")
    ));
    Ok(())
}

declare_format!(pub PS3_PKG = "ps3-pkg", "PlayStation package (PS3/PSP/Vita)", ["pkg"], "application/x-ps3-pkg",
    Probe::Magic(&[(0, b"\x7fPKG")]), ps3_pkg);

async fn ps3_pkg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x80)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.bytes("Magic", 4).emit()?;
    let revision = f.u16("Revision").hex().emit()?;
    let kind = f
        .u16("Type")
        .enumeration(&[(1, "PS3"), (2, "PSP/PS Vita")])
        .emit()?;
    f.u32("Metadata offset").hex().emit()?;
    f.u32("Metadata count").emit()?;
    f.u32("Header size").emit()?;
    let items = f.u32("Item count").emit()?;
    let total = f.u64("Total size").emit()?;
    let data_offset = f.u64("Data offset").hex().emit()?;
    let data_size = f.u64("Data size").emit()?;
    let content_id = f.ascii("Content ID", 48).emit()?;
    cx.emit(Node::new("Encrypted data").span(file.sub(data_offset, data_size)));
    cx.annotate(format!(
        "{} package {content_id}, {items_item}, {total} bytes{}",
        if kind == 1 { "PS3" } else { "PSP/Vita" },
        if revision & 0x8000 != 0 {
            ", retail"
        } else {
            ", debug"
        },
        items_item = plural(items, "item")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo Switch NSP (PFS0) and XCI, Wii WAD, 3DS CIA

declare_format!(pub NSP = "nsp", "Nintendo Switch package (PFS0)", ["nsp", "pfs0", "nsz"], "application/x-switch-nsp",
    Probe::Magic(&[(0, b"PFS0")]), nsp);

async fn nsp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let count = u32_le(&head, 4).unwrap_or(0);
    let strings = u32_le(&head, 8).unwrap_or(0);
    let entries_len = u64::from(count).saturating_mul(24);
    let table = file.sub_exact(16, entries_len)?;
    let names_at = 16u64.saturating_add(entries_len);
    let data_at = names_at.saturating_add(strings.into());
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 16))
            .summary(plural(count, "file")),
    );
    let entries = cx.read(table).await?;
    cx.set_count(Count::Exact(u64::from(count).saturating_add(1)));
    for i in 0..usize::try_from(count).unwrap_or(0) {
        let at = i.saturating_mul(24);
        let offset = u64_le(&entries, at).unwrap_or(0);
        let size = u64_le(&entries, at.saturating_add(8)).unwrap_or(0);
        let name_offset = u32_le(&entries, at.saturating_add(16)).unwrap_or(0);
        let name = cx
            .cstr(file.sub(names_at.saturating_add(name_offset.into()), 256))
            .await
            .map(|(n, _)| n)
            .unwrap_or_default();
        cx.push(
            embedded(
                name,
                input.nested(file.sub(data_at.saturating_add(offset), size)),
            )
            .summary(format!("{size} bytes"))
            .target(table.sub(to_u64(at), 24)),
        )
        .await;
    }
    cx.annotate(format!(
        "PFS0, {count_file}",
        count_file = plural(count, "file")
    ));
    Ok(())
}

fn xci_probe(h: &Head<'_>) -> bool {
    h.at(0x100, b"HEAD")
}

declare_format!(pub XCI = "xci", "Nintendo Switch cartridge image", ["xci"], "application/x-switch-xci",
    Probe::Custom(xci_probe), xci);

async fn xci(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0x100, 0x100)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Secure area start (pages)").emit()?;
    f.u32("Backup area start").hex().emit()?;
    f.u8("Title key decryption index").emit()?;
    let size = f
        .u8("Cartridge size")
        .enumeration(&[
            (0xfa, "1 GB"),
            (0xf8, "2 GB"),
            (0xf0, "4 GB"),
            (0xe0, "8 GB"),
            (0xe1, "16 GB"),
            (0xe2, "32 GB"),
        ])
        .emit()?;
    f.u8("Header version").emit()?;
    f.u8("Flags").hex().emit()?;
    f.u64("Package ID").hex().emit()?;
    f.u32("Valid data end (pages)").emit()?;
    f.u32("Reserved").emit()?;
    f.bytes("IV", 16).emit()?;
    let hfs0 = f.u64("Root HFS0 offset").hex().emit()?;
    f.u64("Root HFS0 header size").emit()?;
    cx.emit(Node::new("Root HFS0").span(file.tail(hfs0)));
    cx.annotate(format!(
        "Switch cartridge, size code {size:#x}, root HFS0 at {hfs0:#x}"
    ));
    Ok(())
}

fn wad_probe(h: &Head<'_>) -> bool {
    u32_be(h.data, 0) == Some(0x20)
        && (h.at(4, b"Is\0\0") || h.at(4, b"ib\0\0") || h.at(4, b"Bk\0\0"))
}

declare_format!(pub WII_WAD = "wii-wad", "Wii installable package (WAD)", ["wad"], "application/x-wii-wad",
    Probe::Custom(wad_probe), wii_wad);

async fn wii_wad(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x20)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Header size").emit()?;
    let kind = f.ascii("Type", 4).emit()?;
    let cert = f.u32("Certificate chain size").emit()?;
    f.u32("Reserved").emit()?;
    let ticket = f.u32("Ticket size").emit()?;
    let tmd = f.u32("TMD size").emit()?;
    let data = f.u32("Data size").emit()?;
    let footer = f.u32("Footer size").emit()?;
    let mut at = 0x40u64;
    for (name, size) in [
        ("Certificate chain", cert),
        ("Ticket", ticket),
        ("Title metadata (TMD)", tmd),
        ("Encrypted content", data),
        ("Footer", footer),
    ] {
        cx.emit(Node::new(name).span(file.sub(at, size.into())));
        at = at.saturating_add(u64::from(size)).next_multiple_of(0x40);
    }
    cx.annotate(format!(
        "Wii WAD ({}), {data} bytes of content",
        kind.trim_end_matches('\0')
    ));
    Ok(())
}

fn cia_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(0x2020) && u16_le(h.data, 4) == Some(0)
}

declare_format!(pub CIA = "cia", "Nintendo 3DS installable archive (CIA)", ["cia"], "application/x-3ds-cia",
    Probe::Custom(cia_probe), cia);

async fn cia(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Header size").emit()?;
    f.u16("Type").emit()?;
    f.u16("Version").emit()?;
    let cert = f.u32("Certificate chain size").emit()?;
    let ticket = f.u32("Ticket size").emit()?;
    let tmd = f.u32("TMD size").emit()?;
    let meta = f.u32("Meta size").emit()?;
    let content = f.u64("Content size").emit()?;
    let mut at = 0x2020u64.next_multiple_of(64);
    for (name, size) in [
        ("Certificate chain", u64::from(cert)),
        ("Ticket", ticket.into()),
        ("Title metadata (TMD)", tmd.into()),
        ("Content", content),
        ("Meta", meta.into()),
    ] {
        if size == 0 {
            continue;
        }
        let span = file.sub(at, size);
        let node = if name == "Content" {
            embedded(name, input.nested(span))
        } else {
            Node::new(name).span(span)
        };
        cx.emit(node);
        at = at.saturating_add(size).next_multiple_of(64);
    }
    cx.annotate(format!("CIA, {content} bytes of content"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows crash dumps and hibernation files

declare_format!(pub KERNEL_DUMP = "windows-kernel-dump", "Windows kernel crash dump", ["dmp"], "application/x-windows-kernel-dump",
    Probe::Magic(&[(0, b"PAGEDU64"), (0, b"PAGEDUMP")]), kernel_dump);

/// `_DUMP_TYPES` (the header's DumpType), with the live-dump types newer
/// debuggers write (kdmp-parser's `DumpType_t`).
const DUMP_TYPES: EnumTable = &[
    (1, "full"),
    (2, "kernel (summary)"),
    (3, "header only"),
    (4, "triage (minidump)"),
    (5, "bitmap full"),
    (6, "bitmap kernel"),
    (7, "automatic"),
    (8, "live kernel memory"),
    (9, "live kernel and user memory"),
    (10, "live complete memory"),
];

const PRODUCT_TYPES: EnumTable = &[(1, "workstation"), (2, "domain controller"), (3, "server")];

/// Offsets of the `DUMP_HEADER32` / `DUMP_HEADER64` fields past the
/// bug check code.
struct DumpLayout {
    header: u64,
    physical_memory: u64,
    physical_memory_len: u64,
    context: u64,
    context_len: u64,
    exception: u64,
    exception_len: u64,
    dump_type: u64,
}

const DUMP32: DumpLayout = DumpLayout {
    header: 0x1000,
    physical_memory: 0x64,
    physical_memory_len: 700,
    context: 0x320,
    context_len: 1200,
    exception: 0x7d0,
    exception_len: 0x50,
    dump_type: 0xf88,
};

const DUMP64: DumpLayout = DumpLayout {
    header: 0x2000,
    physical_memory: 0x88,
    physical_memory_len: 704,
    context: 0x348,
    context_len: 3000,
    exception: 0xf00,
    exception_len: 0x98,
    dump_type: 0xf98,
};

async fn kernel_dump(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let wide = cx.read(file.sub(0, 8)).await? == b"PAGEDU64";
    let l = if wide { &DUMP64 } else { &DUMP32 };
    let head = cx.block(file.sub(0, l.header)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    f.ascii("Valid dump", 4).emit()?;
    let major = f.u32("Major version").emit()?;
    let minor = f.u32("Minor version (build)").emit()?;
    f.uword("Directory table base", wide).hex().emit()?;
    f.uword("PFN database", wide).hex().emit()?;
    f.uword("Loaded module list", wide).hex().emit()?;
    f.uword("Active process list", wide).hex().emit()?;
    let machine = f
        .u32("Machine")
        .enumeration(&[(0x14c, "x86"), (0x8664, "x64"), (0xaa64, "ARM64")])
        .emit()?;
    let processors = f.u32("Processors").emit()?;
    let code = f.u32("Bug check code").hex().emit()?;
    if wide {
        f.skip(4);
    }
    for name in [
        "Bug check parameter 1",
        "Bug check parameter 2",
        "Bug check parameter 3",
        "Bug check parameter 4",
    ] {
        f.uword(name, wide).hex().emit()?;
    }
    f.bytes("Version user", 32).emit()?;
    if !wide {
        f.u8("PAE enabled").emit()?;
        f.u8("KD secondary version").emit()?;
        f.skip(2);
    }
    f.uword("KdDebuggerDataBlock", wide).hex().emit()?;
    let mem = file.sub(l.physical_memory, l.physical_memory_len);
    let runs = u32_le(&head.data, crate::bytes::to_usize(l.physical_memory)).unwrap_or(0);
    f.node(
        Node::new("Physical memory descriptor")
            .span(mem)
            .summary(plural(runs, "run"))
            .lazy(memory_runs, (mem, wide)),
    );
    let context = context_len(machine).map_or_else(
        || Node::new("Context record").span(file.sub(l.context, l.context_len)),
        |len| Node::new("Context record").span(file.sub(l.context, len)),
    );
    f.node(match context.span {
        Some(span) if context_len(machine).is_some() => {
            crate::formats::forensics::minidump::context_node(&cx, span)
                .await
                .renamed("Context record")
        }
        _ => context,
    });
    let exception = file.sub(l.exception, l.exception_len);
    f.node(
        Node::new("Exception record")
            .span(exception)
            .summary(format!(
                "code {:#x}",
                u32_le(&head.data, crate::bytes::to_usize(l.exception)).unwrap_or(0)
            )),
    );
    f.seek(l.dump_type);
    let kind = f.u32("Dump type").enumeration(DUMP_TYPES).emit()?;
    if wide {
        f.skip(4);
        f.u64("Required dump space").emit()?;
        f.u64("System time").filetime().emit()?;
        f.ascii("Comment", 128)
            .with(|c, n| {
                if !c.is_empty() && c.bytes().all(|b| b"PAGE".contains(&b)) {
                    n.summary("not set (PAGE filler)")
                } else {
                    n
                }
            })
            .emit()?;
        f.u64("System up time")
            .desc("In 100-nanosecond units")
            .duration(10_000_000)
            .emit()?;
        f.u32("Minidump fields").hex().emit()?;
        f.u32("Secondary data state").emit()?;
        f.u32("Product type").enumeration(PRODUCT_TYPES).emit()?;
        f.u32("Suite mask").hex().emit()?;
        f.u32("Writer status")
            .hex()
            .with(|&w, n| {
                if w == u32::from_le_bytes(*b"PAGE") {
                    n.summary("not set (PAGE filler)")
                } else {
                    n
                }
            })
            .emit()?;
        f.u8("Unused").emit()?;
        f.u8("KD secondary version").emit()?;
        f.skip(2);
        f.u32("Attributes").hex().emit()?;
        f.u32("Boot ID").emit()?;
    } else {
        f.u32("Minidump fields").hex().emit()?;
        f.u32("Secondary data state").emit()?;
        f.u32("Product type").enumeration(PRODUCT_TYPES).emit()?;
        f.u32("Suite mask").hex().emit()?;
        f.u32("Writer status").emit()?;
        f.u64("Required dump space").emit()?;
        f.skip(16);
        f.u64("System up time").emit()?;
        f.u64("System time").filetime().emit()?;
    }
    let mut pages_at = l.header;
    if wide && matches!(kind, 5 | 6) {
        let bmp = file.sub(l.header, 0x38);
        let b = cx.read_avail(bmp).await?;
        let first = u64_le(&b, 0x20).unwrap_or(0);
        let present = u64_le(&b, 0x28).unwrap_or(0);
        let pages = u64_le(&b, 0x30).unwrap_or(0);
        let bitmap = file.sub(l.header.saturating_add(0x38), pages.div_ceil(8));
        cx.emit(
            Node::new("Bitmap header")
                .span(bmp)
                .summary(format!("{present} of {pages} pages present"))
                .lazy(bitmap_header, bmp),
        );
        cx.emit(
            Node::new("Page bitmap")
                .span(bitmap)
                .summary(format!("{pages} bits")),
        );
        let bitmap_end = l
            .header
            .saturating_add(0x38)
            .saturating_add(pages.div_ceil(8));
        if b.get(..4).is_some_and(|s| s == b"SDMP" || s == b"FDMP")
            && first >= bitmap_end
            && first <= file.len
        {
            pages_at = first;
        }
    }
    if kind == 4 {
        // A triage dump (small memory dump): no memory pages, but a
        // TRIAGE_DUMP header pointing at what was saved, then (Windows 10
        // and later) secondary data blobs from bug check callbacks.
        let t = file.sub(l.header, TRIAGE64_LEN);
        if wide {
            let size = cx
                .read(t.sub(4, 4))
                .await
                .ok()
                .and_then(|b| u32_le(&b, 0))
                .unwrap_or(0);
            cx.emit(
                Node::new("Triage dump")
                    .span(t)
                    .summary(format!("{:#x} bytes", size))
                    .lazy(triage_dump, (file, machine)),
            );
            let size = u64::from(size);
            if size > l.header && size < file.len {
                cx.emit(
                    Node::new("Dump blobs")
                        .span(file.tail(size))
                        .desc("Secondary data from bug check callbacks, after the triage data")
                        .lazy(dump_blobs, file.tail(size)),
                );
            }
        } else {
            cx.emit(
                Node::new("Triage dump")
                    .span(file.tail(l.header))
                    .diag(Diagnostic::unsupported("32-bit triage dump layout")),
            );
        }
    } else {
        cx.emit(Node::new("Memory pages").span(file.tail(pages_at)));
    }
    cx.annotate(format!(
        "Windows {major}.{minor} {} dump, bug check {code:#x}, {processors} CPU(s), machine {machine:#x}",
        lookup(DUMP_TYPES, kind.into()).unwrap_or("crash")
    ));
    Ok(())
}

/// `PHYSICAL_MEMORY_DESCRIPTOR32/64`: the runs of physical pages a full
/// dump stores after its header, in order.
async fn memory_runs(cx: Cx, (span, wide): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let runs = f.u32("Number of runs").emit()?;
    if wide {
        f.skip(4);
    }
    f.uword("Number of pages", wide).emit()?;
    let size = if wide { 16 } else { 8 };
    let fits = f.remaining().checked_div(size).unwrap_or(0);
    for i in 0..u64::from(runs).min(fits) {
        let at = f.pos();
        let base = if wide {
            u64_le(&block.data, crate::bytes::to_usize(at))
        } else {
            u32_le(&block.data, crate::bytes::to_usize(at)).map(u64::from)
        }
        .unwrap_or(0);
        let count = if wide {
            u64_le(&block.data, crate::bytes::to_usize(at.saturating_add(8)))
        } else {
            u32_le(&block.data, crate::bytes::to_usize(at.saturating_add(4))).map(u64::from)
        }
        .unwrap_or(0);
        f.node(
            Node::new(format!("Run {i}"))
                .span(f.peek_span(size))
                .summary(format!(
                    "page {base:#x}, {count_page} (physical {:#x})",
                    base.saturating_mul(0x1000),
                    count_page = plural(count, "page")
                )),
        );
        f.skip(size);
    }
    if u64::from(runs) > fits {
        cx.diag(
            Diagnostic::malformed(format!(
                "{runs_run} do not fit the descriptor",
                runs_run = plural(runs, "run")
            ))
            .at(span),
        );
    }
    Ok(())
}

/// The size of a thread context in a crash dump, by machine.
fn context_len(machine: u32) -> Option<u64> {
    match machine {
        0xaa64 => Some(0x390),
        0x8664 => Some(0x4d0),
        0x14c => Some(0x2cc),
        _ => None,
    }
}

const TRIAGE64_LEN: u64 = 0x80;

/// `TRIAGE_DUMP64`: where a small memory dump keeps what it saved, as
/// offsets from the start of the file. Field names are those WinDbg's
/// `.dumpdebug` prints, checked against its output for a Windows 11 dump.
#[derive(Clone, Debug, Default)]
struct Triage {
    size: u32,
    valid: u32,
    context: u32,
    exception: u32,
    mm: u32,
    unloaded: u32,
    prcb: u32,
    process: u32,
    thread: u32,
    stack: u32,
    stack_len: u32,
    drivers: u32,
    driver_count: u32,
    pool: u32,
    pool_len: u32,
    top: u64,
    debugger: u32,
    debugger_len: u32,
    blocks: u32,
    block_count: u32,
}

fn triage_layout(f: &mut Fields<'_>, _: &()) -> Result<Triage> {
    let mut t = Triage::default();
    f.u32("ServicePackBuild").emit()?;
    t.size = f.u32("SizeOfDump").hex().emit()?;
    t.valid = f.u32("ValidOffset").hex().emit()?;
    t.context = f.u32("ContextOffset").hex().emit()?;
    t.exception = f.u32("ExceptionOffset").hex().emit()?;
    t.mm = f.u32("MmOffset").hex().emit()?;
    t.unloaded = f.u32("UnloadedDriversOffset").hex().emit()?;
    t.prcb = f.u32("PrcbOffset").hex().emit()?;
    t.process = f.u32("ProcessOffset").hex().emit()?;
    t.thread = f.u32("ThreadOffset").hex().emit()?;
    t.stack = f.u32("CallStackOffset").hex().emit()?;
    t.stack_len = f.u32("SizeOfCallStack").hex().emit()?;
    t.drivers = f.u32("DriverListOffset").hex().emit()?;
    t.driver_count = f.u32("DriverCount").emit()?;
    t.pool = f.u32("StringPoolOffset").hex().emit()?;
    t.pool_len = f.u32("StringPoolSize").hex().emit()?;
    f.u32("BrokenDriverOffset").hex().emit()?;
    f.u32("TriageOptions").hex().emit()?;
    t.top = f.u64("TopOfStack").hex().emit()?;
    f.u32("BStoreOffset").hex().emit()?;
    f.u32("SizeOfBStore").hex().emit()?;
    f.u64("LimitOfBStore").hex().emit()?;
    f.u64("DataPageAddress").hex().emit()?;
    f.u32("DataPageOffset").hex().emit()?;
    f.u32("DataPageSize").hex().emit()?;
    t.debugger = f.u32("DebuggerDataOffset").hex().emit()?;
    t.debugger_len = f.u32("DebuggerDataSize").hex().emit()?;
    t.blocks = f.u32("DataBlocksOffset").hex().emit()?;
    t.block_count = f.u32("DataBlocksCount").emit()?;
    Ok(t)
}

/// `DUMP_DRIVER_ENTRY64`: a name offset into the string pool, then a
/// `KLDR_DATA_TABLE_ENTRY64`.
const DRIVER64_LEN: u64 = 0x90;
/// `DUMP_UNLOADED_DRIVERS64`: `UNICODE_STRING64`, the first 12 characters
/// of the name, start and end address.
const UNLOADED64_LEN: u64 = 0x38;
/// `TRIAGE_DATA_BLOCK`: address, file offset, size.
const DATA_BLOCK_LEN: u64 = 0x10;

async fn triage_dump(cx: Cx, (file, machine): (Span, u32)) -> Result<()> {
    let span = file.sub(0x2000, TRIAGE64_LEN);
    let t = parse(&cx, span, LE, &(), triage_layout).await?;
    cx.emit(struct_node("TRIAGE_DUMP64", span, LE, (), triage_layout));
    // The opaque kernel structures run to the next thing the header
    // points at.
    let mut marks: Vec<u64> = [
        0x2000,
        t.size,
        t.valid,
        t.context,
        t.exception,
        t.mm,
        t.unloaded,
        t.prcb,
        t.process,
        t.thread,
        t.stack,
        t.drivers,
        t.pool,
        t.debugger,
        t.blocks,
    ]
    .iter()
    .map(|&o| u64::from(o))
    .filter(|&o| o > 0)
    .collect();
    marks.sort_unstable();
    let until_next = |at: u32| {
        let at = u64::from(at);
        let end = marks
            .iter()
            .copied()
            .find(|&m| m > at)
            .unwrap_or(u64::from(t.size));
        file.sub(at, end.saturating_sub(at))
    };
    if t.context == 0x348 || t.exception == 0xf00 {
        // Usually the header's own context and exception records.
        cx.emit(
            Node::new("Context and exception")
                .summary("the dump header's context and exception records"),
        );
    }
    if t.context > 0 && t.context != 0x348 {
        let len = context_len(machine).unwrap_or(0);
        let span = file.sub(t.context.into(), len);
        cx.emit(if len > 0 {
            crate::formats::forensics::minidump::context_node(&cx, span).await
        } else {
            Node::new("Context").span(until_next(t.context))
        });
    }
    if t.exception > 0 && t.exception != 0xf00 {
        cx.emit(
            Node::new("Exception record")
                .span(file.sub(t.exception.into(), 0x98))
                .desc("EXCEPTION_RECORD64"),
        );
    }
    for (name, at, desc) in [
        ("Mm information", t.mm, "Memory manager state at the crash"),
        (
            "PRCB",
            t.prcb,
            "The crashing processor's KPRCB (version-specific)",
        ),
        (
            "Process",
            t.process,
            "The current process's EPROCESS (version-specific)",
        ),
        (
            "Thread",
            t.thread,
            "The current thread's ETHREAD (version-specific)",
        ),
    ] {
        if at > 0 {
            cx.emit(Node::new(name).span(until_next(at)).desc(desc));
        }
    }
    if t.stack > 0 {
        cx.emit(
            Node::new("Call stack")
                .span(file.sub(t.stack.into(), t.stack_len.into()))
                .summary(format!(
                    "{:#x} bytes of stack from {:#x}",
                    t.stack_len, t.top
                )),
        );
    }
    if t.drivers > 0 {
        cx.emit(
            Node::new("Drivers")
                .span(file.sub(
                    t.drivers.into(),
                    u64::from(t.driver_count).saturating_mul(DRIVER64_LEN),
                ))
                .summary(plural(t.driver_count, "driver"))
                .lazy(triage_drivers, (file, t.clone())),
        );
    }
    if t.unloaded > 0 {
        cx.emit(
            Node::new("Unloaded drivers")
                .span(until_next(t.unloaded))
                .lazy(triage_unloaded, until_next(t.unloaded)),
        );
    }
    if t.pool > 0 {
        cx.emit(
            Node::new("String pool")
                .span(file.sub(t.pool.into(), t.pool_len.into()))
                .desc("Driver names: a character count, UTF-16, a terminator, 8-byte aligned"),
        );
    }
    if t.debugger > 0 {
        let span = file.sub(t.debugger.into(), t.debugger_len.into());
        cx.emit(
            struct_node("Debugger data", span, LE, (), kdbg_layout).summary("KDDEBUGGER_DATA64"),
        );
    }
    if t.blocks > 0 {
        cx.emit(
            Node::new("Data blocks")
                .span(file.sub(
                    t.blocks.into(),
                    u64::from(t.block_count).saturating_mul(DATA_BLOCK_LEN),
                ))
                .summary(plural(t.block_count, "block"))
                .lazy(triage_blocks, (file, t.blocks, t.block_count)),
        );
    }
    if t.valid > 0 {
        let span = file.sub(t.valid.into(), 4);
        let b = cx.read(span).await?;
        let mut node = Node::new("Valid marker")
            .span(span)
            .value(Value::Text(String::from_utf8_lossy(&b).into_owned()));
        if b != b"TRGD" {
            node = node.diag(Diagnostic::warning("not the TRGD marker"));
        }
        cx.emit(node);
    }
    Ok(())
}

/// The start of `KDDEBUGGER_DATA64`: its list header, owner tag (`KDBG`)
/// and size, then the kernel's base address.
fn kdbg_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("List.Flink").hex().emit()?;
    f.u64("List.Blink").hex().emit()?;
    f.ascii("OwnerTag", 4).emit()?;
    f.u32("Size").hex().emit()?;
    f.u64("KernBase").hex().emit()?;
    Ok(())
}

async fn triage_drivers(cx: Cx, (file, t): (Span, Triage)) -> Result<()> {
    let list = file.sub_exact(
        t.drivers.into(),
        u64::from(t.driver_count).saturating_mul(DRIVER64_LEN),
    )?;
    let pool_span = file.sub(t.pool.into(), u64::from(t.pool_len).min(1 << 20));
    let pool = cx.read(pool_span).await?;
    let pool_base = u64::from(t.pool);
    let mut at = 0;
    for i in 0..t.driver_count {
        let span = list.sub(at, DRIVER64_LEN);
        let e = cx.read(span).await?;
        at = at.saturating_add(DRIVER64_LEN);
        let name_at = u32_le(&e, 0).unwrap_or(0);
        let base = u64_le(&e, 0x38).unwrap_or(0);
        let size = u32_le(&e, 0x48).unwrap_or(0);
        let name = u64::from(name_at)
            .checked_sub(pool_base)
            .and_then(|o| usize::try_from(o).ok())
            .and_then(|o| {
                let chars = u32_le(&pool, o)?;
                let from = o.checked_add(4)?;
                let bytes = usize::try_from(chars).ok()?.checked_mul(2)?;
                let b = pool.get(from..from.checked_add(bytes)?)?;
                Some(crate::text::utf16(b, LE))
            });
        let node = Node::new(name.unwrap_or_else(|| format!("Driver {i}")))
            .span(span)
            .value(Value::UInt {
                value: base,
                bits: 64,
                radix: crate::value::Radix::Hex,
            })
            .summary(format!("{:#x} bytes", size))
            .lazy(driver_entry, span);
        cx.push(node).await;
    }
    Ok(())
}

async fn driver_entry(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("DriverNameOffset").hex().emit()?;
    f.skip(4);
    f.u64("InLoadOrderLinks.Flink").hex().emit()?;
    f.u64("InLoadOrderLinks.Blink").hex().emit()?;
    f.u64("ExceptionTable").hex().emit()?;
    f.u32("ExceptionTableSize").hex().emit()?;
    f.skip(4);
    f.u64("GpValue").hex().emit()?;
    f.u64("NonPagedDebugInfo").hex().emit()?;
    f.u64("DllBase").hex().emit()?;
    f.u64("EntryPoint").hex().emit()?;
    f.u32("SizeOfImage").hex().emit()?;
    f.skip(4);
    f.u16("FullDllName.Length").emit()?;
    f.u16("FullDllName.MaximumLength").emit()?;
    f.skip(4);
    f.u64("FullDllName.Buffer").hex().emit()?;
    f.u16("BaseDllName.Length").emit()?;
    f.u16("BaseDllName.MaximumLength").emit()?;
    f.skip(4);
    f.u64("BaseDllName.Buffer").hex().emit()?;
    f.u32("Flags").hex().emit()?;
    f.u16("LoadCount").emit()?;
    f.skip(2 + 8);
    f.u32("CheckSum").hex().emit()?;
    f.skip(4);
    f.u32("TimeDateStamp")
        .hex()
        .desc("The image's link stamp (a hash for reproducible builds)")
        .emit()?;
    Ok(())
}

async fn triage_unloaded(cx: Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub(0, 8)).await?;
    let count = u32_le(&head, 0).unwrap_or(0);
    cx.emit(Node::new("Count").span(span.sub(0, 4)).value(Value::UInt {
        value: count.into(),
        bits: 32,
        radix: crate::value::Radix::Dec,
    }));
    let fits = span.len.saturating_sub(8) / UNLOADED64_LEN;
    let mut at = 8u64;
    for _ in 0..u64::from(count).min(fits) {
        let espan = span.sub(at, UNLOADED64_LEN);
        at = at.saturating_add(UNLOADED64_LEN);
        let e = cx.read(espan).await?;
        let len = usize::from(u16_le(&e, 0).unwrap_or(0)).min(24);
        let name = crate::text::utf16(
            e.get(0x10..0x10usize.saturating_add(len))
                .unwrap_or_default(),
            LE,
        );
        let start = u64_le(&e, 0x28).unwrap_or(0);
        let end = u64_le(&e, 0x30).unwrap_or(0);
        cx.push(
            Node::new(name)
                .span(espan)
                .summary(format!("{start:#x}..{end:#x}"))
                .desc("The first 12 characters of the driver's name, and its address range"),
        )
        .await;
    }
    if u64::from(count) > fits {
        cx.diag(Diagnostic::malformed(format!("{count} unloaded drivers do not fit")).at(span));
    }
    Ok(())
}

async fn triage_blocks(cx: Cx, (file, at, count): (Span, u32, u32)) -> Result<()> {
    let list = file.sub_exact(at.into(), u64::from(count).saturating_mul(DATA_BLOCK_LEN))?;
    let mut pos = 0;
    for _ in 0..count {
        let span = list.sub(pos, DATA_BLOCK_LEN);
        pos = pos.saturating_add(DATA_BLOCK_LEN);
        let b = cx.read(span).await?;
        let address = u64_le(&b, 0).unwrap_or(0);
        let offset = u32_le(&b, 8).unwrap_or(0);
        let size = u32_le(&b, 12).unwrap_or(0);
        cx.push(
            Node::new(format!("{address:#x}"))
                .span(span)
                .target(file.sub(offset.into(), size.into()))
                .summary(format!("{size:#x} bytes at {offset:#x}"))
                .desc("Kernel memory saved for the debugger: address, file offset, size"),
        )
        .await;
    }
    Ok(())
}

/// The secondary data after the triage data: a file header (`DumpBlob`,
/// header size, build number), then blobs, each a header (header size, a
/// GUID tag naming the callback's data, data size, padding before and
/// after) and its data. The layout is the one this Windows 11 dump shows:
/// 17 blobs that tile the region exactly; what follows them is left
/// undecoded.
async fn dump_blobs(cx: Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub(0, 0x10)).await?;
    if head.get(..8) != Some(b"DumpBlob".as_slice()) {
        cx.emit(
            Node::new("Unknown data")
                .span(span)
                .diag(Diagnostic::unsupported("no DumpBlob header")),
        );
        return Ok(());
    }
    let header_len = u64::from(u32_le(&head, 8).unwrap_or(0x10)).max(0x10);
    cx.emit(
        Node::new("Blob file header")
            .span(span.sub(0, header_len))
            .summary(format!("build {}", u32_le(&head, 12).unwrap_or(0) & 0xffff)),
    );
    let mut at = header_len;
    let mut index = 0u64;
    while at.saturating_add(0x20) <= span.len {
        let h = cx.read(span.sub(at, 0x20)).await?;
        let hlen = u64::from(u32_le(&h, 0).unwrap_or(0));
        let data = u64::from(u32_le(&h, 0x14).unwrap_or(0));
        let pre = u64::from(u32_le(&h, 0x18).unwrap_or(0));
        let post = u64::from(u32_le(&h, 0x1c).unwrap_or(0));
        let total = hlen
            .saturating_add(pre)
            .saturating_add(data)
            .saturating_add(post);
        if hlen < 0x20 || total > span.len.saturating_sub(at) {
            break;
        }
        let tag = crate::formats::util::datakit::guid_le(h.get(4..20).unwrap_or_default());
        let bspan = span.sub(at, total);
        cx.push(
            Node::new(format!("Blob {index}"))
                .span(bspan)
                .value(Value::Guid(tag))
                .summary(format!("{data:#x} bytes"))
                .target(bspan.sub(hlen.saturating_add(pre), data)),
        )
        .await;
        at = at.saturating_add(total);
        index = index.saturating_add(1);
    }
    if at < span.len {
        cx.emit(
            Node::new("Remaining data")
                .span(span.tail(at))
                .summary("not decoded"),
        );
    }
    Ok(())
}

/// The bitmap dump header (`SDMP`/`FDMP`) at 0x2000 of 64-bit bitmap
/// dumps.
async fn bitmap_header(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Signature", 4).emit()?;
    f.ascii("Valid dump", 4).emit()?;
    f.bytes("Padding", 0x18).emit()?;
    f.u64("First page").hex().emit()?;
    f.u64("Present pages").emit()?;
    f.u64("Pages").emit()?;
    Ok(())
}

declare_format!(pub HIBERFIL = "hiberfil", "Windows hibernation file", ["sys"], "application/x-windows-hiberfil",
    Probe::Magic(&[(0, b"HIBR"), (0, b"hibr"), (0, b"WAKE"), (0, b"wake"), (0, b"RSTR")]), hiberfil);

async fn hiberfil(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x80)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let sig = f.ascii("Signature", 4).emit()?;
    let version = f.u32("Image type / version").emit()?;
    f.u32("Checksum").hex().emit()?;
    f.u32("Length self").emit()?;
    cx.emit(
        Node::new("Compressed memory image")
            .span(file.tail(0x1000))
            .lazy(xpress_blocks, input),
    );
    let state = match sig.as_str() {
        "HIBR" | "hibr" => "hibernated",
        "WAKE" | "wake" => "resumed (stale)",
        _ => "restore pending",
    };
    cx.annotate(format!("hibernation file, {state}, version {version}"));
    Ok(())
}

/// The signature of the Xpress blocks of Windows XP to 7 hibernation files.
const XPRESS_MAGIC: &[u8; 8] = b"\x81\x81xpress";

/// Lists the Xpress blocks of a (Windows XP to 7) hibernation file: a
/// 32-byte header (signature, then a word holding the page count minus one
/// in its low 10 bits and the compressed size minus one above), then Plain
/// LZ77 data padded to 8 bytes; a block whose compressed size is that of
/// its pages is stored. Blocks follow each other in runs between the
/// memory range tables, so the image is scanned for them. Later versions
/// use a different layout, which is not decoded.
async fn xpress_blocks(cx: Cx, input: Input) -> Result<()> {
    const WINDOW: u64 = 0x10000;
    let file = input.span;
    let mut at = 0x1000u64;
    let mut index = 0u64;
    // Runs of blocks are separated by single table pages: give up after
    // 1 MiB without a block.
    let mut misses = 0u32;
    while at.saturating_add(0x20) <= file.len && misses < 16 {
        let window = cx.read_avail(file.sub(at, WINDOW)).await?;
        let found = window
            .chunks(8)
            .position(|c| c.starts_with(XPRESS_MAGIC))
            .map(|i| to_u64(i).saturating_mul(8));
        let Some(offset) = found else {
            at = at.saturating_add(WINDOW);
            misses = misses.saturating_add(1);
            cx.checkpoint().await;
            continue;
        };
        misses = 0;
        at = at.saturating_add(offset);
        let head = cx.read_avail(file.sub(at, 0x20)).await?;
        let word = u32_le(&head, 8).unwrap_or(0);
        let pages = u64::from(word & 0x3ff).saturating_add(1);
        let size = u64::from(word >> 10).saturating_add(1);
        let decoded = pages.saturating_mul(0x1000);
        let data = file.sub(at.saturating_add(0x20), size);
        let codec = if size >= decoded {
            crate::codec::Codec::Stored
        } else {
            crate::codec::Codec::Xpress {
                size: Some(decoded),
            }
        };
        let total = size.saturating_add(7) & !7;
        cx.progress_in(file, file.offset.saturating_add(at));
        cx.push(
            Node::new(format!("Xpress block {index}"))
                .span(file.sub(at, total.saturating_add(0x20)))
                .summary(format!(
                    "{pages_page}, {}",
                    if size >= decoded {
                        "stored".to_owned()
                    } else {
                        format!("{size} bytes compressed")
                    },
                    pages_page = plural(pages, "page")
                ))
                .lazy(xpress_block, (input, at, data, codec, decoded)),
        )
        .await;
        index = index.saturating_add(1);
        at = at.saturating_add(0x20).saturating_add(total);
    }
    if index == 0 {
        cx.diag(Diagnostic::unsupported(
            "hibernation image without Xpress blocks (Windows 8 and later layout)",
        ));
    }
    Ok(())
}

async fn xpress_block(
    cx: Cx,
    (input, at, data, codec, decoded): (Input, u64, crate::span::Span, crate::codec::Codec, u64),
) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(at, 0x20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 8).emit()?;
    f.u32("Pages and size")
        .hex()
        .with(|&w, n| {
            n.summary(format!(
                "{}, {} bytes",
                plural((w & 0x3ff).saturating_add(1), "page"),
                (w >> 10).saturating_add(1)
            ))
        })
        .emit()?;
    f.bytes("Reserved", 20).emit()?;
    cx.emit(crate::formats::content(
        "Pages",
        input,
        data,
        codec,
        Some(decoded),
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// dm-verity superblock, btrfs send streams

declare_format!(pub VERITY = "dm-verity", "dm-verity hash device", ["img", "verity"], "application/x-dm-verity",
    Probe::Magic(&[(0, b"verity\0\0")]), verity);

record! {
    pub struct VeritySuperblock {
        signature: ascii[8] "Signature",
        version: u32 "Version",
        hash_type: u32 "Hash type",
        uuid: bytes[16] "UUID",
        algorithm: ascii[32] "Hash algorithm",
        data_block: u32 "Data block size",
        hash_block: u32 "Hash block size",
        data_blocks: u64 "Data blocks",
        salt_size: u16 "Salt size",
        _padding: bytes[6] "Padding",
        salt: bytes[256] "Salt",
    }
}

async fn verity(cx: Cx, input: Input) -> Result<()> {
    let h: VeritySuperblock =
        emit_record(&cx, input.span.sub(0, VeritySuperblock::SIZE), LE).await?;
    cx.emit(Node::new("Hash tree").span(input.span.tail(u64::from(h.hash_block))));
    cx.annotate(format!(
        "dm-verity v{}, {}, {} data blocks of {} bytes",
        h.version,
        h.algorithm.trim_end_matches('\0'),
        h.data_blocks,
        h.data_block
    ));
    Ok(())
}

declare_format!(pub BTRFS_SEND = "btrfs-send", "btrfs send stream", ["btrfs", "send"], "application/x-btrfs-send",
    Probe::Magic(&[(0, b"btrfs-stream\0")]), btrfs_send);

const SEND_COMMANDS: EnumTable = &[
    (1, "SUBVOL"),
    (2, "SNAPSHOT"),
    (3, "MKFILE"),
    (4, "MKDIR"),
    (5, "MKNOD"),
    (6, "MKFIFO"),
    (7, "MKSOCK"),
    (8, "SYMLINK"),
    (9, "RENAME"),
    (10, "LINK"),
    (11, "UNLINK"),
    (12, "RMDIR"),
    (13, "SET_XATTR"),
    (14, "REMOVE_XATTR"),
    (15, "WRITE"),
    (16, "CLONE"),
    (17, "TRUNCATE"),
    (18, "CHMOD"),
    (19, "CHOWN"),
    (20, "UTIMES"),
    (21, "END"),
    (22, "UPDATE_EXTENT"),
];

async fn btrfs_send(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let version = u32_le(&cx.read(file.sub(13, 4)).await?, 0).unwrap_or(0);
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 17))
            .summary(format!("version {version}")),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(17);
    let mut commands = 0u32;
    while cur.remaining() >= 10 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let cmd = cur.u16().await?;
        let _crc = cur.u32().await?;
        cur.skip(len.into());
        commands = commands.saturating_add(1);
        let mut node = Node::new(
            lookup(SEND_COMMANDS, cmd.into())
                .map_or_else(|| format!("command {cmd}"), str::to_owned),
        )
        .span(cur.since(start));
        // The first attribute of most commands is the path.
        let attrs = cx
            .read_avail(file.sub(start.saturating_add(10), u64::from(len).min(512)))
            .await?;
        if u16_le(&attrs, 0) == Some(15) {
            let plen = usize::from(u16_le(&attrs, 2).unwrap_or(0));
            node = node.summary(
                String::from_utf8_lossy(
                    attrs
                        .get(4..4usize.saturating_add(plen))
                        .unwrap_or_default(),
                )
                .into_owned(),
            );
        }
        cx.progress_in(file, file.offset.saturating_add(start));
        cx.push(node).await;
        if cmd == 21 {
            break;
        }
    }
    cx.annotate(format!(
        "btrfs send stream v{version}, {commands_command}",
        commands_command = plural(commands, "command")
    ));
    Ok(())
}
