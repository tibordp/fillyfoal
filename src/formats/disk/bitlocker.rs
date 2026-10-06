//! BitLocker encrypted volumes (Windows 7 and later).
//!
//! The volume starts with a boot sector whose OEM id is `-FVE-FS-`; it
//! points at three copies of the FVE metadata block, which hold the
//! encryption method, the volume GUID and a list of metadata entries (key
//! protectors, description, ...).

use crate::bytes::{to_u64, u16_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::size;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const SIGNATURE: &[u8] = b"-FVE-FS-";
/// Metadata entries listed per block before assuming corruption.
const MAX_ENTRIES: usize = 1024;

pub static FORMAT: Format = Format {
    name: "bitlocker",
    title: "BitLocker encrypted volume",
    extensions: &["img", "bde"],
    mime: "application/x-bitlocker",
    probe: Probe::Magic(&[(3, SIGNATURE)]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    /// The boot sector fields BitLocker uses (BPB-shaped).
    pub struct BootSector {
        jump: bytes[3] "Jump instruction",
        oem: ascii[8] "Signature",
        bytes_per_sector: u16 "Bytes per sector",
        sectors_per_cluster: u8 "Sectors per cluster",
        reserved: u16 "Reserved sectors",
        _bpb: bytes[12] "BPB (unused)",
        hidden: u32 "Hidden sectors",
        _bpb2: bytes[4] "BPB (unused)",
        _ext: bytes[124] "Extended BPB (unused)",
        volume_guid: guid "Volume identifier",
        fve1: u64 "FVE metadata block 1 offset" .hex(),
        fve2: u64 "FVE metadata block 2 offset" .hex(),
        fve3: u64 "FVE metadata block 3 offset" .hex(),
    }
}

record! {
    /// FVE metadata block header (version 2).
    pub struct BlockHeader {
        signature: ascii[8] "Signature",
        len: u16 "Size",
        version: u16 "Version",
        _unknown: u16 "Unknown",
        _unknown2: u16 "Unknown",
        volume_size: u64 "Encrypted volume size" .with(|&v, n| n.summary(size(v))),
        _unknown3: u32 "Unknown",
        header_sectors: u32 "Volume header sectors",
        block1: u64 "FVE metadata block 1 offset" .hex(),
        block2: u64 "FVE metadata block 2 offset" .hex(),
        block3: u64 "FVE metadata block 3 offset" .hex(),
        volume_header: u64 "Volume header offset" .hex(),
    }
}

const METHODS: EnumTable = &[
    (0x0000, "not encrypted"),
    (0x1000, "stretch key"),
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

record! {
    /// A metadata entry header; the value follows.
    pub struct EntryHeader {
        size: u16 "Entry size",
        kind: u16 "Entry type" .hex() .enumeration(ENTRY_TYPES),
        value_type: u16 "Value type" .hex() .enumeration(VALUE_TYPES),
        version: u16 "Version",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let boot_span = vol.sub(0, BootSector::SIZE);
    let boot = parse(&cx, boot_span, LE, &(), BootSector::layout).await?;
    cx.emit(BootSector::node("Boot sector", vol.sub(0, 512), LE));
    let mut method = None;
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
        let meta = vol.sub(offset.saturating_add(64), MetadataHeader::SIZE);
        let header = parse(&cx, meta, LE, &(), MetadataHeader::layout).await.ok();
        let len = header
            .as_ref()
            .map_or(64, |h| u64::from(h.size).saturating_add(64));
        if method.is_none() {
            method = header;
        }
        cx.emit(
            Node::new(name)
                .span(vol.sub(offset, len))
                .summary(format!("at {offset:#x}"))
                .lazy(block, (vol, offset)),
        );
    }
    cx.annotate(match method {
        Some(m) => format!(
            "BitLocker volume, {}",
            lookup(METHODS, m.method.into()).unwrap_or("unknown encryption method")
        ),
        None => "BitLocker volume".to_owned(),
    });
    Ok(())
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
    let mut at = 0usize;
    let mut count = 0usize;
    while let Some(len) = u16_le(&data, at) {
        let len = usize::from(len);
        if len < 8 || count >= MAX_ENTRIES {
            break;
        }
        let kind = u16_le(&data, at.saturating_add(2)).unwrap_or(0);
        let value_type = u16_le(&data, at.saturating_add(4)).unwrap_or(0);
        let span = entries.sub(to_u64(at), to_u64(len));
        let mut node = Node::new(lookup(ENTRY_TYPES, kind.into()).map_or_else(
            || format!("Entry {kind:#06x}"),
            |n| {
                let mut s = n.to_owned();
                if let Some(first) = s.get_mut(..1) {
                    first.make_ascii_uppercase();
                }
                s
            },
        ))
        .span(span)
        .lazy(entry, span);
        if value_type == 0x0002 {
            let text = data
                .get(at.saturating_add(8)..at.saturating_add(len))
                .map(|b| crate::text::utf16z(b, LE).0)
                .unwrap_or_default();
            node = node.value(Value::Text(text));
        } else if let Some(name) = lookup(VALUE_TYPES, value_type.into()) {
            node = node.summary(name);
        }
        cx.push(node).await;
        at = at.saturating_add(len);
        count = count.saturating_add(1);
    }
    if count >= MAX_ENTRIES {
        cx.diag(Diagnostic::limit(format!(
            "more than {MAX_ENTRIES} metadata entries"
        )));
    }
    Ok(())
}

async fn entry(cx: Cx, span: Span) -> Result<()> {
    let header = parse(
        &cx,
        span.sub(0, EntryHeader::SIZE),
        LE,
        &(),
        EntryHeader::layout,
    )
    .await?;
    cx.emit(EntryHeader::node(
        "Header",
        span.sub(0, EntryHeader::SIZE),
        LE,
    ));
    let value = span.tail(EntryHeader::SIZE);
    let data = cx.read_avail(value).await?;
    let node = Node::new("Value").span(value);
    cx.emit(match header.value_type {
        0x0002 => node.value(Value::Text(crate::text::utf16z(&data, LE).0)),
        0x0008 => {
            // Volume master key: key identifier GUID, last change, protection.
            let protection = u16_le(&data, 26).unwrap_or(0);
            let modified = u64_le(&data, 16).unwrap_or(0);
            node.summary(format!(
                "protection {}, modified {}",
                lookup(PROTECTION, protection.into()).unwrap_or("unknown"),
                crate::render::value(&Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(modified)
                })
            ))
        }
        0x000f => node.summary(format!(
            "offset {:#x}, size {:#x}",
            u64_le(&data, 0).unwrap_or(0),
            u64_le(&data, 8).unwrap_or(0)
        )),
        _ => node.summary(format!("{} bytes", data.len())),
    });
    Ok(())
}

const PROTECTION: EnumTable = &[
    (0x0000, "clear key"),
    (0x0100, "TPM"),
    (0x0200, "startup key"),
    (0x0500, "TPM and PIN"),
    (0x0800, "recovery password"),
    (0x2000, "password"),
];
