//! BitLocker encrypted volumes (Windows 7 and later).
//!
//! The volume starts with a FAT32-shaped boot sector whose OEM id is
//! `-FVE-FS-`; it points at three copies of the FVE metadata block. Each
//! block holds a block header (the encrypted volume size and where the
//! original volume header was moved), a metadata header (encryption method,
//! volume GUID) and a list of metadata entries: volume master keys with
//! their key protectors (nested entries: stretch keys, AES-CCM encrypted
//! keys, external keys), the full volume encryption key, a description,
//! the location of the relocated volume header. Everything else on the
//! volume is encrypted data.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::qcow::Regions;
use crate::formats::disk::{guid_le, size};
use crate::formats::util::arcutil::ByteReader;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;
const SIGNATURE: &[u8] = b"-FVE-FS-";
/// Metadata entries listed per block (or nested value) before assuming
/// corruption.
const MAX_ENTRIES: usize = 1024;
/// Nesting of entries within entries followed at most.
const MAX_NESTING: usize = 4;

pub static FORMAT: Format = Format {
    name: "bitlocker",
    title: "BitLocker encrypted volume",
    extensions: &["img", "bde"],
    mime: "application/x-bitlocker",
    probe: Probe::Magic(&[(3, SIGNATURE)]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    /// The volume header: a FAT32-shaped boot sector.
    pub struct BootSector {
        jump: bytes[3] "Jump instruction",
        oem: ascii[8] "Signature",
        bytes_per_sector: u16 "Bytes per sector",
        sectors_per_cluster: u8 "Sectors per cluster",
        reserved: u16 "Reserved sectors",
        fats: u8 "Number of FATs",
        root_entries: u16 "Root directory entries",
        total16: u16 "Total sectors (16-bit)",
        media: u8 "Media descriptor" .hex(),
        fat16: u16 "Sectors per FAT (16-bit)",
        per_track: u16 "Sectors per track",
        heads: u16 "Heads",
        hidden: u32 "Hidden sectors" .desc("Sectors before the volume (its partition's start)"),
        total32: u32 "Total sectors (32-bit)",
        fat32: u32 "Sectors per FAT (32-bit)",
        ext_flags: u16 "Extended flags" .hex(),
        fs_version: u16 "File system version",
        root_cluster: u32 "Root directory cluster",
        fsinfo: u16 "FSInfo sector",
        backup: u16 "Backup boot sector",
        _reserved: bytes[12] "Reserved",
        drive: u8 "Drive number" .hex(),
        _reserved2: u8 "Reserved",
        ext_sig: u8 "Extended boot signature" .hex(),
        serial: u32 "Volume serial number" .hex(),
        label: ascii[11] "Volume label",
        fs_type: ascii[8] "File system type",
        code: bytes[70] "Boot code",
        volume_guid: guid "BitLocker identifier",
        fve1: u64 "FVE metadata block 1 offset" .hex(),
        fve2: u64 "FVE metadata block 2 offset" .hex(),
        fve3: u64 "FVE metadata block 3 offset" .hex(),
        code2: bytes[307] "Boot code",
        _reserved3: bytes[3] "Reserved",
        signature: u16 "Boot signature" .hex(),
    }
}

record! {
    /// FVE metadata block header (version 2).
    pub struct BlockHeader {
        signature: ascii[8] "Signature",
        len: u16 "Size",
        version: u16 "Version" .with(|&v, n| n.summary(match v { 1 => "Windows Vista", 2 => "Windows 7 or later", _ => "unknown" })),
        _unknown: u16 "Unknown",
        _unknown2: u16 "Unknown",
        volume_size: u64 "Encrypted volume size" .with(|&v, n| n.summary(size(v))),
        _unknown3: u32 "Unknown",
        header_sectors: u32 "Volume header sectors",
        block1: u64 "FVE metadata block 1 offset" .hex(),
        block2: u64 "FVE metadata block 2 offset" .hex(),
        block3: u64 "FVE metadata block 3 offset" .hex(),
        volume_header: u64 "Volume header offset" .hex() .desc("Where the original (encrypted) volume header was moved"),
    }
}

const METHODS: EnumTable = &[
    (0x0000, "not encrypted"),
    (0x1000, "stretch key"),
    (0x1001, "stretch key"),
    (0x2000, "AES-CCM 256"),
    (0x2001, "AES-CCM 256"),
    (0x2002, "AES-CCM 256"),
    (0x2003, "AES-CCM 256"),
    (0x2004, "AES-CCM 256"),
    (0x2005, "AES-CCM 256"),
    (0x8000, "AES-CBC 128 with diffuser"),
    (0x8001, "AES-CBC 256 with diffuser"),
    (0x8002, "AES-CBC 128"),
    (0x8003, "AES-CBC 256"),
    (0x8004, "AES-XTS 128"),
    (0x8005, "AES-XTS 256"),
];

record! {
    /// FVE metadata header, after the block header.
    pub struct MetadataHeader {
        size: u32 "Metadata size",
        version: u32 "Version",
        header_size: u32 "Header size",
        size_copy: u32 "Metadata size (copy)",
        volume_guid: guid "Volume identifier",
        nonce: u32 "Next nonce counter",
        method: u32 "Encryption method" .hex() .enumeration(METHODS),
        created: u64 "Created" .filetime(),
    }
}

const ENTRY_TYPES: EnumTable = &[
    (0x0000, "property"),
    (0x0002, "volume master key"),
    (0x0003, "full volume encryption key"),
    (0x0004, "validation"),
    (0x0006, "startup key"),
    (0x0007, "description"),
    (0x000b, "FVEK backup"),
    (0x000f, "volume header block"),
];

const VALUE_TYPES: EnumTable = &[
    (0x0000, "erased"),
    (0x0001, "key"),
    (0x0002, "UTF-16 string"),
    (0x0003, "stretch key"),
    (0x0004, "use key"),
    (0x0005, "AES-CCM encrypted key"),
    (0x0006, "TPM encoded key"),
    (0x0007, "validation"),
    (0x0008, "volume master key"),
    (0x0009, "external key"),
    (0x000a, "update"),
    (0x000b, "error"),
    (0x000f, "offset and size"),
    (0x0012, "recovery backup"),
];

const PROTECTION: EnumTable = &[
    (0x0000, "clear key"),
    (0x0100, "TPM"),
    (0x0200, "startup key"),
    (0x0500, "TPM and PIN"),
    (0x0800, "recovery password"),
    (0x2000, "password"),
];

/// What the layout map needs from a metadata block.
#[derive(Clone, Copy, Debug)]
struct Block {
    span: Span,
    volume_size: u64,
    volume_header: Option<Span>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let boot_span = vol.sub(0, BootSector::SIZE);
    let boot = parse(&cx, boot_span, LE, &(), BootSector::layout).await?;
    cx.emit(
        BootSector::node("Volume header", boot_span, LE).summary(format!(
            "{}-byte sectors, metadata at {:#x}, {:#x}, {:#x}",
            boot.bytes_per_sector, boot.fve1, boot.fve2, boot.fve3
        )),
    );
    let mut method = None;
    let mut blocks = Vec::new();
    let mut description = None;
    for (i, offset) in [boot.fve1, boot.fve2, boot.fve3].into_iter().enumerate() {
        let name = format!("FVE metadata block {}", i.saturating_add(1));
        let span = vol.sub(offset, 64);
        let sig = cx.read_avail(span.sub(0, 8)).await?;
        if offset == 0 || sig != SIGNATURE {
            cx.emit(
                Node::new(name)
                    .span(span)
                    .diag(Diagnostic::malformed(format!(
                        "no FVE metadata at {offset:#x}"
                    ))),
            );
            continue;
        }
        let bh = parse(&cx, span, LE, &(), BlockHeader::layout).await.ok();
        let meta = vol.sub(offset.saturating_add(64), MetadataHeader::SIZE);
        let header = parse(&cx, meta, LE, &(), MetadataHeader::layout).await.ok();
        let len = header
            .as_ref()
            .map_or(64, |h| u64::from(h.size).saturating_add(64));
        let block_span = vol.sub(offset, len);
        if description.is_none() {
            description = block_description(&cx, block_span).await?;
        }
        if let Some(h) = &header
            && method.is_none()
        {
            method = Some((h.method, h.volume_guid));
        }
        blocks.push(Block {
            span: block_span,
            volume_size: bh.as_ref().map_or(0, |b| b.volume_size),
            volume_header: bh.as_ref().and_then(|b| {
                (b.volume_header != 0).then(|| {
                    vol.sub(
                        b.volume_header,
                        u64::from(b.header_sectors)
                            .saturating_mul(boot.bytes_per_sector.max(512).into()),
                    )
                })
            }),
        });
        cx.emit(
            Node::new(name)
                .span(block_span)
                .summary(format!("at {offset:#x}, {}", size(len)))
                .lazy(block, (vol, offset)),
        );
    }
    let mut summary = match method {
        Some((m, guid)) => format!(
            "BitLocker volume, {}, volume {guid}",
            lookup(METHODS, m.into()).unwrap_or("unknown encryption method")
        ),
        None => "BitLocker volume".to_owned(),
    };
    if let Some(d) = description {
        summary.push_str(&format!(", {d:?}"));
    }
    cx.annotate(summary);
    if let Some(first) = blocks.first().copied() {
        cx.emit(
            Node::new("Volume layout")
                .span(vol)
                .summary("metadata, the relocated volume header and the encrypted data")
                .lazy(layout, (vol, Arc::new(blocks), first)),
        );
    }
    Ok(())
}

/// The description entry of a metadata block, for the summary.
async fn block_description(cx: &Cx, block: Span) -> Result<Option<String>> {
    let data = cx.read_avail(block).await?;
    let mut at = 64usize.saturating_add(crate::bytes::to_usize(MetadataHeader::SIZE));
    for _ in 0..MAX_ENTRIES {
        let Some(len) = u16_le(&data, at).map(usize::from) else {
            break;
        };
        if len < 8 {
            break;
        }
        if u16_le(&data, at.saturating_add(2)) == Some(7)
            && u16_le(&data, at.saturating_add(4)) == Some(2)
        {
            let text = data
                .get(at.saturating_add(8)..at.saturating_add(len))
                .map(|b| crate::text::utf16z(b, LE).0);
            return Ok(text);
        }
        at = at.saturating_add(len);
    }
    Ok(None)
}

async fn block(cx: Cx, (vol, offset): (Span, u64)) -> Result<()> {
    let header = vol.sub(offset, BlockHeader::SIZE);
    cx.emit(BlockHeader::node("Block header", header, LE));
    let meta_span = vol.sub(
        offset.saturating_add(BlockHeader::SIZE),
        MetadataHeader::SIZE,
    );
    let meta = parse(&cx, meta_span, LE, &(), MetadataHeader::layout).await?;
    cx.emit(MetadataHeader::node("Metadata header", meta_span, LE));
    // Entries follow the metadata header, up to the metadata size.
    let entries = vol.sub(
        meta_span.end().saturating_sub(vol.offset),
        u64::from(meta.size).saturating_sub(MetadataHeader::SIZE),
    );
    let data = cx.read_avail(entries).await?;
    let count = push_entries(&cx, &data, entries, 0).await;
    if count >= MAX_ENTRIES {
        cx.diag(Diagnostic::limit(format!(
            "more than {MAX_ENTRIES} metadata entries"
        )));
    }
    Ok(())
}

/// Pushes the entries in `data` (at `span`); returns how many.
async fn push_entries(cx: &Cx, data: &[u8], span: Span, depth: usize) -> usize {
    let mut at = 0usize;
    let mut count = 0usize;
    while let Some(len) = u16_le(data, at) {
        let len = usize::from(len);
        if len < 8 || count >= MAX_ENTRIES {
            break;
        }
        let bytes = data.get(at..at.saturating_add(len)).unwrap_or_default();
        let espan = span.sub(to_u64(at), to_u64(len));
        cx.push(entry_node(bytes, espan, depth)).await;
        at = at.saturating_add(len);
        count = count.saturating_add(1);
    }
    let rest = to_u64(data.len()).saturating_sub(to_u64(at));
    if rest > 0 && count < MAX_ENTRIES {
        cx.push(
            Node::new("Trailing bytes")
                .span(span.tail(to_u64(at)))
                .summary(format!("{rest} bytes")),
        )
        .await;
    }
    count
}

fn capitalized(s: &str) -> String {
    let mut s = s.to_owned();
    if let Some(first) = s.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    s
}

/// A metadata entry: name, value and summary from its header and value;
/// its fields (and nested entries) on expansion.
fn entry_node(bytes: &[u8], span: Span, depth: usize) -> Node {
    let kind = u16_le(bytes, 2).unwrap_or(0);
    let value_type = u16_le(bytes, 4).unwrap_or(0);
    let value = bytes.get(8..).unwrap_or_default();
    let name = match (kind, lookup(ENTRY_TYPES, kind.into())) {
        (0, _) => lookup(VALUE_TYPES, value_type.into())
            .map_or_else(|| format!("Value {value_type:#06x}"), capitalized),
        (_, Some(n)) => capitalized(n),
        (_, None) => format!("Entry {kind:#06x}"),
    };
    let mut node = Node::new(name).span(span);
    match value_type {
        0x0002 => node = node.value(Value::Text(crate::text::utf16z(value, LE).0)),
        0x0008 => {
            let protection = u16_le(value, 26).unwrap_or(0);
            node = node.summary(format!(
                "{}, key {}",
                lookup(PROTECTION, protection.into()).unwrap_or("unknown protection"),
                guid_le(value.get(..16).unwrap_or_default())
            ));
        }
        0x0009 => {
            node = node.summary(format!(
                "key {}",
                guid_le(value.get(..16).unwrap_or_default())
            ));
        }
        0x000f => {
            node = node.summary(format!(
                "offset {:#x}, size {}",
                u64_le(value, 0).unwrap_or(0),
                size(u64_le(value, 8).unwrap_or(0))
            ));
        }
        0x0001 | 0x0003 => {
            let m = u32_le(value, 0).unwrap_or(0);
            node = node.summary(lookup(METHODS, m.into()).unwrap_or("unknown method"));
        }
        t => {
            if let Some(n) = lookup(VALUE_TYPES, t.into())
                && kind != 0
            {
                node = node.summary(n);
            }
        }
    }
    node.lazy(entry_fields, (span, Arc::new(bytes.to_vec()), depth))
}

async fn entry_fields(cx: Cx, (span, bytes, depth): (Span, Arc<Vec<u8>>, usize)) -> Result<()> {
    let mut r = ByteReader::new(&bytes, span);
    let _ = r.u16("Entry size", LE);
    let kind = r.u16("Entry type", LE).unwrap_or(0);
    r.with(|n| n.value(enum16(kind, ENTRY_TYPES)));
    let value_type = r.u16("Value type", LE).unwrap_or(0);
    r.with(|n| n.value(enum16(value_type, VALUE_TYPES)));
    let _ = r.u16("Version", LE);
    // Nested entries start here (for the value types that have them).
    let mut nested_at = None;
    match value_type {
        0x0001 => {
            method(&mut r);
            let n = r.remaining();
            let _ = r.bytes("Key", to_u64(n));
        }
        0x0002 => {
            let n = r.remaining();
            let at = r.at;
            if r.skip(to_u64(n)).is_some() {
                let text = crate::text::utf16z(bytes.get(at..).unwrap_or_default(), LE).0;
                r.push(
                    Node::new("String")
                        .span(r.since(at))
                        .value(Value::Text(text)),
                );
            }
        }
        0x0003 => {
            method(&mut r);
            let _ = r.bytes("Salt", 16);
            nested_at = Some(r.at);
        }
        0x0004 => {
            method(&mut r);
            let n = r.remaining();
            let _ = r.bytes("Data", to_u64(n));
        }
        0x0005 => {
            let _ = r.u64("Nonce time", LE);
            r.with(|n| {
                n.value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(u64_le(&bytes, 8).unwrap_or(0)),
                })
            });
            let _ = r.u32("Nonce counter", LE);
            let n = r.remaining();
            let _ = r.bytes("MAC and encrypted key", to_u64(n));
            r.with(|n| n.summary("AES-CCM: 16-byte MAC, then the encrypted key structure"));
        }
        0x0008 | 0x0009 => {
            let at = r.at;
            let _ = r.bytes("Key identifier", 16);
            r.with(|n| {
                n.value(Value::Guid(guid_le(
                    bytes.get(at..at.saturating_add(16)).unwrap_or_default(),
                )))
            });
            let _ = r.u64("Last modified", LE);
            let t = u64_le(&bytes, at.saturating_add(16)).unwrap_or(0);
            r.with(|n| {
                n.value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(t),
                })
            });
            if value_type == 0x0008 {
                let _ = r.u16("Unknown", LE);
                let p = r.u16("Protection type", LE).unwrap_or(0);
                r.with(|n| n.value(enum16(p, PROTECTION)));
            }
            nested_at = Some(r.at);
        }
        0x000f => {
            let _ = r.u64("Offset", LE);
            r.with(|n| {
                n.value(Value::UInt {
                    value: u64_le(&bytes, 8).unwrap_or(0),
                    bits: 64,
                    radix: Radix::Hex,
                })
            });
            let s = r.u64("Size", LE).unwrap_or(0);
            r.with(|n| n.summary(size(s)));
        }
        _ => {
            let n = r.remaining();
            if n > 0 {
                let _ = r.bytes("Data", to_u64(n));
            }
        }
    }
    let nodes = r.into_nodes();
    for n in nodes.iter() {
        cx.emit(n.clone());
    }
    if let Some(at) = nested_at {
        let rest = bytes.get(at..).unwrap_or_default();
        if depth >= MAX_NESTING {
            cx.diag(Diagnostic::limit("metadata entries nested too deep"));
        } else if !rest.is_empty() {
            push_entries(&cx, rest, span.tail(to_u64(at)), depth.saturating_add(1)).await;
        }
    }
    Ok(())
}

fn method(r: &mut ByteReader<'_>) {
    if let Some(m) = r.u32("Encryption method", LE) {
        r.with(|n| {
            n.value(Value::Enum {
                raw: m.into(),
                bits: 32,
                name: lookup(METHODS, m.into()),
            })
        });
    }
}

fn enum16(raw: u16, table: EnumTable) -> Value {
    Value::Enum {
        raw: raw.into(),
        bits: 16,
        name: lookup(table, raw.into()),
    }
}

/// The volume: header, metadata blocks, relocated volume header, encrypted
/// data and (for a conversion in progress) data not yet encrypted.
async fn layout(cx: Cx, (vol, blocks, first): (Span, Arc<Vec<Block>>, Block)) -> Result<()> {
    let mut r = Regions::default();
    r.add(0, 512, "Volume header", None);
    for (i, b) in blocks.iter().enumerate() {
        r.span(
            vol,
            b.span,
            match i {
                0 => "FVE metadata block 1",
                1 => "FVE metadata block 2",
                _ => "FVE metadata block 3",
            },
        );
    }
    if let Some(h) = first.volume_header {
        r.span(vol, h, "Relocated volume header (encrypted)");
    }
    if first.volume_size > 0 && first.volume_size < vol.len {
        r.add(
            first.volume_size,
            vol.len.saturating_sub(first.volume_size),
            "Not yet encrypted",
            None,
        );
    }
    r.emit_named(
        &cx,
        vol,
        "Encrypted data",
        "sectors encrypted with the full volume encryption key",
    )
    .await;
    Ok(())
}
